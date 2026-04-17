from app.db import Base

from sqlalchemy.orm import Mapped,mapped_column

from sqlalchemy import Integer,String

class UserModel(Base):
    __tablename__ = "users"

    id:Mapped[int] = mapped_column(Integer,primary_key=True)

    email:Mapped[str] = mapped_column(String,unique=True)
    password:Mapped[str] = mapped_column(String)

