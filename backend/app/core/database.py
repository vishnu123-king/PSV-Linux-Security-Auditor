import logging
from typing import AsyncGenerator
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase
from backend.app.core.config import get_settings

logger = logging.getLogger(__name__)


class Base(DeclarativeBase):
    pass


settings = get_settings()

# Engine configuration with connection pooling for PostgreSQL / single-thread args for SQLite
connect_args = {}
if "sqlite" in settings.DATABASE_URL:
    connect_args = {"check_same_thread": False}

engine = create_async_engine(
    settings.DATABASE_URL,
    echo=False,
    future=True,
    connect_args=connect_args,
    pool_pre_ping=True
)

async_session_factory = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False
)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with async_session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


from sqlalchemy import text


async def init_db() -> None:
    """Initialize database tables and auto-migrate missing columns for SQLite."""
    # Import all models so Base has metadata registered
    import backend.app.models  # noqa: F401

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

        # If using SQLite, auto-migrate missing columns for existing tables
        if "sqlite" in settings.DATABASE_URL:
            for table_name, table in Base.metadata.tables.items():
                res = await conn.execute(text(f"PRAGMA table_info({table_name})"))
                existing_cols = {row[1] for row in res.fetchall()}
                if not existing_cols:
                    continue

                for col in table.columns:
                    if col.name not in existing_cols:
                        col_type = col.type.compile(engine.dialect)
                        sql = f"ALTER TABLE {table_name} ADD COLUMN {col.name} {col_type}"
                        try:
                            await conn.execute(text(sql))
                            logger.info(f"Auto-migrated: Added column '{col.name}' to '{table_name}'")
                        except Exception as e:
                            logger.warning(f"Could not add column '{col.name}' to '{table_name}': {e}")

    logger.info("Database schema verified and created.")
