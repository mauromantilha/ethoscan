from collections.abc import Generator
from pathlib import Path

from sqlalchemy import create_engine, text
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.config import get_settings


class Base(DeclarativeBase):
    pass


def _make_engine():
    settings = get_settings()
    connect_args = {"check_same_thread": False} if settings.database_url.startswith("sqlite") else {}
    return create_engine(settings.database_url, pool_pre_ping=True, connect_args=connect_args)


engine = _make_engine()
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def _ensure_sqlite_columns() -> None:
    settings = get_settings()
    if not settings.database_url.startswith("sqlite"):
        return
    with engine.begin() as conn:
        try:
            cols = {row[1] for row in conn.execute(text("PRAGMA table_info(jobs)"))}
        except Exception:  # noqa: BLE001
            return
        if cols and "tool_runs" not in cols:
            conn.execute(text("ALTER TABLE jobs ADD COLUMN tool_runs JSON DEFAULT '{}'"))
        try:
            fcols = {row[1] for row in conn.execute(text("PRAGMA table_info(findings)"))}
        except Exception:  # noqa: BLE001
            return
        if fcols and "mocked" not in fcols:
            conn.execute(text("ALTER TABLE findings ADD COLUMN mocked BOOLEAN DEFAULT 0"))


def init_db() -> None:
    from app import models  # noqa: F401

    Base.metadata.create_all(bind=engine)
    _ensure_sqlite_columns()
    try:
        from alembic import command
        from alembic.config import Config

        cfg_path = Path(__file__).resolve().parents[1] / "alembic.ini"
        if cfg_path.exists():
            cfg = Config(str(cfg_path))
            cfg.set_main_option("sqlalchemy.url", get_settings().database_url)
            command.upgrade(cfg, "head")
    except Exception:  # noqa: BLE001
        # create_all + ensure columns cobrem SQLite local se Alembic falhar
        pass
