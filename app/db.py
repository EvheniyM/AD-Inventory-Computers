import time
from collections.abc import Generator

from sqlalchemy import create_engine, text
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.config import get_settings


class Base(DeclarativeBase):
    pass


settings = get_settings()
engine = create_engine(settings.database_url, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)


def run_lightweight_migrations() -> None:
    statements = [
        "ALTER TABLE machines ADD COLUMN IF NOT EXISTS manual_user_key VARCHAR(255)",
        "ALTER TABLE machines ADD COLUMN IF NOT EXISTS hardware_cpu VARCHAR(255)",
        "ALTER TABLE machines ADD COLUMN IF NOT EXISTS hardware_ram VARCHAR(255)",
        "ALTER TABLE machines ADD COLUMN IF NOT EXISTS hardware_disks TEXT",
        "ALTER TABLE machines ADD COLUMN IF NOT EXISTS hardware_gpu VARCHAR(255)",
        "ALTER TABLE machines ADD COLUMN IF NOT EXISTS hardware_motherboard VARCHAR(255)",
        "ALTER TABLE machines ADD COLUMN IF NOT EXISTS hardware_monitors TEXT",
        "ALTER TABLE machines ADD COLUMN IF NOT EXISTS hardware_network TEXT",
        "ALTER TABLE machines ADD COLUMN IF NOT EXISTS hardware_updated_at TIMESTAMP WITH TIME ZONE",
    ]
    with engine.begin() as connection:
        if engine.dialect.name == "postgresql":
            connection.execute(text("SET LOCAL lock_timeout = '5s'"))
        for statement in statements:
            connection.execute(text(statement))
        if engine.dialect.name == "postgresql":
            connection.execute(text("ALTER TABLE machines ALTER COLUMN hardware_ram TYPE TEXT"))


def init_db(retries: int = 20, delay_seconds: float = 1.5) -> None:
    from app import models  # noqa: F401

    last_error: Exception | None = None
    for _ in range(retries):
        try:
            Base.metadata.create_all(bind=engine)
            run_lightweight_migrations()
            return
        except Exception as exc:  # pragma: no cover - startup resilience
            last_error = exc
            time.sleep(delay_seconds)
    if last_error:
        raise last_error


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
