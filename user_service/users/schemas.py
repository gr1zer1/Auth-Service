from pydantic import BaseModel, ConfigDict, EmailStr


class UserSchema(BaseModel):
    email: EmailStr
    password: str
    telegram_id: int | None = None


class UserResponseSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    email: str
    is_active: bool
    is_service: bool
    telegram_id: int | None = None


class TelegramLinkSchema(BaseModel):
    telegram_id: int
