import logging
import sys
from config import config
from database.postgres import PostgresDatabase

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("cloudpulse.database.migrate")


def run_migrations():
    """
    Standalone migration runner for PostgreSQL.
    Can be invoked during CD pipelines, init containers, or local database provisioning.
    """
    logger.info("Starting CloudPulse PostgreSQL schema migration on host: %s", config.POSTGRES_HOST)
    if not config.POSTGRES_PASSWORD:
        logger.error("POSTGRES_PASSWORD is not set. Cannot run PostgreSQL migrations.")
        sys.exit(1)

    try:
        db = PostgresDatabase(
            host=config.POSTGRES_HOST,
            port=config.POSTGRES_PORT,
            database=config.POSTGRES_DB,
            user=config.POSTGRES_USER,
            password=config.POSTGRES_PASSWORD,
            sslmode=config.POSTGRES_SSLMODE,
        )
        db.initialize_schema()
        logger.info("CloudPulse PostgreSQL migrations applied successfully.")
    except Exception as e:
        logger.error("Migration failed: %s", str(e))
        sys.exit(1)


if __name__ == "__main__":
    run_migrations()
