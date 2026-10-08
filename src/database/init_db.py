import logging
from src.config.settings import settings
from src.database.session import SessionLocal, check_database_health
from src.database.migrations.runner import run_migrations
from src.database.seed.seeder import seed_database

logger = logging.getLogger("backend.init")


def initialize_database() -> None:
    """
    Orchestrates database migration and optional demo seed on startup.
    """
    logger.info("Initializing database layer...")
    
    # 1. Run migrations / create tables
    run_migrations()

    # 2. Check health
    if not check_database_health():
        raise RuntimeError("Database health check failed during initialization")

    # 3. Seed demo data if configured
    if settings.DEMO_MODE:
        db = SessionLocal()
        try:
            seed_database(db)
        finally:
            db.close()

    logger.info("Database layer initialized and ready.")
