from pydantic import BaseModel,field_validator,model_validator,ConfigDict

from fastapi.responses import JSONResponse

class UserCreate(BaseModel):

    email:str
    password:str

    

    @field_validator("email")
    @classmethod
    def validate_email(cls, value: str) -> str:
        if "@" not in value:
            raise ValueError("Invalid email")
        return value.lower().strip()


    @field_validator("password")
    @classmethod
    def validate_password(cls, value: str) -> str:
        if len(value) < 8:
            raise ValueError("Password must be at least 8 characters")
        return value

class UserResponse(BaseModel):
    id:int
    email:str
    model_config = ConfigDict(from_attributes=True)


class UserLogin(BaseModel):
    email:str
    password:str
    model_config = ConfigDict(from_attributes=True)
