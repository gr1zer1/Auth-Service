from fastapi import APIRouter, Depends, HTTPException, status,Response,Cookie
from fastapi.security import OAuth2PasswordBearer,OAuth2PasswordRequestForm

from .model import UserCreate,UserResponse,UserLogin

from typing import Annotated

from sqlalchemy.ext.asyncio import AsyncSession

from sqlalchemy import select

from app.models.user import UserModel

from app.db import get_db

from app.auth import create_access_token,create_refresh_token,decode_token

from app.utility import verify_password,hash_password

SessionDep = Annotated[AsyncSession,Depends(get_db)]

router = APIRouter()

oauth2_scheme = OAuth2PasswordBearer("/user/login")

@router.post("/users",response_model=UserResponse)
async def create_new_user(user:UserCreate,db:SessionDep) -> UserResponse:

    stmt = select(UserModel).where(UserModel.email == user.email  )
    res = await db.execute(stmt)

    data = res.scalar_one_or_none()

    if data != None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT,detail="User with same email already exists")

    new_user = UserModel(
        email = user.email,
        password = hash_password(user.password),
    )
    
    db.add(new_user)

    await db.commit()

    await db.refresh(new_user)

    return new_user
       
    


@router.get("/users",response_model=list[UserResponse])
async def all_users(db:SessionDep):
    
    stmt = select(UserModel)

    res = await db.execute(stmt)

    data = res.scalars().all()

    return data


@router.get("/user",response_model=UserResponse)
async def current_user(id:int,db:SessionDep) -> UserResponse:
    stmt = select(UserModel).where(id == UserModel.id)
    res = await db.execute(stmt)
    data = res.scalar_one_or_none()

    if data == None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,detail="No user with that id")
    
    return data



@router.post("/login")
async def login(
    response: Response,
    db: SessionDep,
    form: OAuth2PasswordRequestForm = Depends(),
) -> dict:
    stmt = select(UserModel).where(UserModel.email == form.username)
    res = await db.execute(stmt)
    data = res.scalar_one_or_none()

    if not data or not verify_password(form.password, data.password):
        raise HTTPException(status_code=401, detail="Incorrect email or password")

    refresh_token = create_refresh_token(data.id)
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        max_age=30*24*60*60,
        httponly=True,
        samesite="lax",
        secure=True
    )

    return {"access_token": create_access_token(data.id), "token_type": "bearer"}


@router.post("/refresh")
async def refresh(refresh_token:str = Cookie(None)) -> dict:
    if not refresh_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,detail="Incorrect refresh token")
    
    payload = decode_token(refresh_token)

    if payload.get("type") != "refresh":
        raise HTTPException(status_code=401, detail="Invalid token type")

    user_id = int(payload.get("sub"))
    access_token = create_access_token(user_id=user_id)

    return {"access_token": access_token}


async def get_current_user(
    db: SessionDep,
    token: str = Depends(oauth2_scheme)
) -> UserModel:
    payload = decode_token(token)
    if payload.get("type") != "access":
        raise HTTPException(status_code=401, detail="Invalid token type")
    user = await db.get(UserModel, int(payload["sub"]))
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user

@router.get("/me", response_model=UserResponse)
async def me(user: UserModel = Depends(get_current_user)) -> UserResponse:
    return user
