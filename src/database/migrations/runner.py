import logging
import os
from alembic.config import Config
from alembic import command
from src.config.settings import settings
from src.database.session import Base, engine

logger = logging.getLogger("backend.migrations")


def run_migrations() -> None:
    """
    Executes database schema migrations.
    For local development and SQLite/PostgreSQL, ensures all metadata tables exist
    and synchronizes Alembic revision head state.
    """
    try:
        if ":memory:" in settings.DATABASE_URL:
            Base.metadata.create_all(bind=engine)
            logger.info("In-memory database tables initialized via SQLAlchemy Base.metadata.")
            return

        ini_path = os.path.abspath("alembic.ini")
        if os.path.exists(ini_path):
            alembic_cfg = Config(ini_path)
            alembic_cfg.set_main_option("sqlalchemy.url", settings.DATABASE_URL)
            logger.info("Applying Alembic migrations to head...")
            # If alembic upgrade head runs
            try:
                command.upgrade(alembic_cfg, "head")
                logger.info("Alembic migrations completed successfully.")
                return
            except Exception as e:
                logger.warning(f"Alembic command upgrade encountered: {e}. Falling back to Base.metadata.create_all.")
        
        # Safe fallback: create_all is fully idempotent and ensures tables exist
        Base.metadata.create_all(bind=engine)
        logger.info("Database tables initialized via SQLAlchemy Base.metadata.")
    except Exception as exc:
        logger.error(f"Migration execution error: {exc}")
        raise
