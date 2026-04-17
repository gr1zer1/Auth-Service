from typing import Annotated, List

from core import (
    UserModel,
    config,
    create_access_token,
    create_refresh_token,
    db_helper,
    decode_token,
    hash_password,
    verify_password,
)
from fastapi import APIRouter, Depends, Header, HTTPException, Query, Response, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from users.schemas import TelegramLinkSchema, UserResponseSchema, UserSchema

SessionDep = Annotated[AsyncSession, Depends(db_helper.get_session)]

router = APIRouter(tags=["Users"])


async def get_current_user(
    session: SessionDep, authorization: str | None = Header(default=None)
) -> UserModel:
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Authorization header",
        )

    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authorization scheme",
        )

    payload = decode_token(token)
    user_id = payload.get("sub")

    stmt = select(UserModel).where(UserModel.id == int(user_id))
    result = await session.execute(stmt)
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
        )

    return user


@router.post("/register", response_model=UserResponseSchema)
async def register(user: UserSchema, session: SessionDep) -> UserResponseSchema:
    stmt = select(UserModel).where(UserModel.email == user.email)
    existing_user_result = await session.execute(stmt)

    if existing_user_result.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="User with this email already exists",
        )

    if user.telegram_id is not None:
        stmt = select(UserModel).where(UserModel.telegram_id == user.telegram_id)
        existing_telegram_user = await session.execute(stmt)
        if existing_telegram_user.scalar_one_or_none():
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="This Telegram account is already linked to another user",
            )

    new_user = UserModel(
        email=user.email,
        password=hash_password(user.password),
        is_service=(user.email == "bot@service.com"),
        telegram_id=user.telegram_id,
    )

    session.add(new_user)
    await session.commit()
    await session.refresh(new_user)

    return new_user


@router.get("/telegram/{telegram_id}", response_model=UserResponseSchema)
async def get_user_by_telegram_id(
    telegram_id: int, session: SessionDep
) -> UserResponseSchema:
    stmt = select(UserModel).where(UserModel.telegram_id == telegram_id)
    result = await session.execute(stmt)
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found for this Telegram ID",
        )

    return user


@router.get("/by-email", response_model=UserResponseSchema)
async def get_user_by_email(
    session: SessionDep, email: str = Query(...)
) -> UserResponseSchema:
    stmt = select(UserModel).where(UserModel.email == email)
    result = await session.execute(stmt)
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
        )

    return user


@router.post("/login")
async def login(
    response: Response,
    form: Annotated[OAuth2PasswordRequestForm, Depends()],
    session: SessionDep,
) -> dict:
    stmt = select(UserModel).where(UserModel.email == form.username)
    user_result = await session.execute(stmt)
    user_data = user_result.scalar_one_or_none()

    if not user_data or not verify_password(form.password, user_data.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
        )

    access_token = create_access_token(user_data.id, is_service=user_data.is_service)
    refresh_token = create_refresh_token(user_data.id)

    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        max_age=config.refresh_token_expire_days
        * 24
        * 60
        * 60,
        httponly=True,
        samesite="lax",
        secure=True,
    )

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": UserResponseSchema.model_validate(user_data),
    }


@router.post("/telegram/link", response_model=UserResponseSchema)
async def link_telegram_account(
    payload: TelegramLinkSchema,
    session: SessionDep,
    current_user: UserModel = Depends(get_current_user),
) -> UserResponseSchema:
    stmt = select(UserModel).where(
        UserModel.telegram_id == payload.telegram_id,
        UserModel.id != current_user.id,
    )
    result = await session.execute(stmt)
    existing_user = result.scalar_one_or_none()

    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="This Telegram account is already linked to another user",
        )

    current_user.telegram_id = payload.telegram_id
    await session.commit()
    await session.refresh(current_user)

    return current_user


@router.get("", response_model=List[UserResponseSchema])
async def get_all_users(session: SessionDep) -> List[UserResponseSchema]:
    stmt = select(UserModel)
    result = await session.execute(stmt)
    return result.scalars().all()


@router.get("/{user_id}", response_model=UserResponseSchema)
async def get_user(user_id: int, session: SessionDep) -> UserResponseSchema:
    stmt = select(UserModel).where(UserModel.id == user_id)
    result = await session.execute(stmt)
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
        )

    return user
