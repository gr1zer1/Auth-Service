from datetime import datetime, timedelta, timezone

from fastapi import HTTPException, status
from jose import JWTError, jwt

from .config import config


def create_access_token(user_id: int, is_service: bool = False) -> str:
    expire = datetime.now(timezone.utc) + timedelta(
        minutes=config.access_token_expire_minutes
    )
    return jwt.encode(
        {
            "sub": str(user_id),
            "exp": expire,
            "type": "access",
            "is_service": is_service,
        },
        key=config.jwt_secret_key,
        algorithm=config.jwt_algorithm,
    )


def create_refresh_token(user_id: int) -> str:
    expire = datetime.now(timezone.utc) + timedelta(
        days=config.refresh_token_expire_days
    )
    return jwt.encode(
        {"sub": str(user_id), "exp": expire, "type": "refresh"},
        config.jwt_secret_key,
        config.jwt_algorithm,
    )


def decode_token(token: str) -> dict:
    try:
        payload = jwt.decode(
            token=token, key=config.jwt_secret_key, algorithms=[config.jwt_algorithm]
        )
        return payload
    except JWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid Token!"
        )
