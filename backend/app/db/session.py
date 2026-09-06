"""Async engine and session factory.

`statement_timeout` is set on every connection. An unbounded query is a denial-of-service
primitive: one pathological search can pin a pool connection indefinitely, and thirty of
them take the API down without a single exploit.
"""
from collections.abc import AsyncIterator

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.core.config import get_settings

settings = get_settings()

engine = create_async_engine(
    str(settings.database_url).replace("postgresql://", "postgresql+asyncpg://"),
    pool_size=settings.db_pool_size,
    max_overflow=settings.db_max_overflow,
    pool_pre_ping=True,
    pool_recycle=1800,
    echo=False,
    connect_args={
        "server_settings": {
            "application_name": "chat-api",
            "statement_timeout": "8000",
            "idle_in_transaction_session_timeout": "15000",
        },
        "ssl": "require" if settings.is_production else None,
    },
)

SessionLocal = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)


async def get_db() -> AsyncIterator[AsyncSession]:
    async with SessionLocal() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise
