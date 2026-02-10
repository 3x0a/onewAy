from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.settings import settings

engine = create_async_engine(settings.database.database_url, echo=False, future=True)

AsyncSessionLocal = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)
