from pydantic import BaseModel, ConfigDict, EmailStr,Field, field_validator


class UserSchema(BaseModel):
    email: EmailStr
    password: str
    role: str
    


class UserResponseSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    email: str


class ChangePasswordRequestSchema(BaseModel):
    old_password: str
    new_password: str = Field(min_length=8)

    @field_validator("new_password")
    def passwords_not_same(cls, new, values):
        if new == values.data.get("old_password"):
            raise ValueError("New password must differ from old one")
        return new