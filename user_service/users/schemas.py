from pydantic import BaseModel, ConfigDict, EmailStr


class UserSchema(BaseModel):
    email: EmailStr
    password: str
    role: str
    


class UserResponseSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    email: str
    role: str