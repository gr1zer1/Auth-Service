from sqlalchemy.ext.asyncio import create_async_engine,AsyncSession,async_sessionmaker

from sqlalchemy.orm import DeclarativeBase 



DATABASE_URL = "postgresql+asyncpg://user:password@db:5432/app"

engine = create_async_engine(DATABASE_URL)

SessionLocal = async_sessionmaker(engine,expire_on_commit=False)

class Base(DeclarativeBase):
    pass


async def get_db():
    async with SessionLocal() as session:
        yield session