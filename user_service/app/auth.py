from jose import JWTError,jwt

from datetime import timedelta,datetime,timezone

from fastapi import HTTPException,status

ALGORITHM = "HS256"

SECRET_KEY = "top_secret_key"

def create_access_token(user_id:int) -> str:
    expire =  datetime.now(timezone.utc) + timedelta(minutes=15)

    return jwt.encode(
        {"sub":str(user_id),"exp":expire,"type":"access"},

        key=SECRET_KEY,
        algorithm=ALGORITHM,

    )


def create_refresh_token(user_id:int) -> str:
    expire =  datetime.now(timezone.utc) + timedelta(days=30)

    return jwt.encode(
        {"sub":str(user_id),"exp":expire,"type":"refresh"},
        SECRET_KEY,
        ALGORITHM,

    )


def decode_token(token:str) ->dict:
    try:
        payload = jwt.decode(
            token=token,
            key=SECRET_KEY,
            algorithms=[ALGORITHM]
        )
        return payload
    except JWTError as e:
        print(e)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,detail="Invalid Token!")


