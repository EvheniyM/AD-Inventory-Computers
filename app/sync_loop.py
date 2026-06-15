import logging
import os
import time

from app.config import get_settings
from app.db import SessionLocal, init_db
from app.logging_config import configure_logging
from app.sync_service import run_sync


def configure_timezone(timezone_name: str) -> None:
    os.environ["TZ"] = timezone_name
    if hasattr(time, "tzset"):
        time.tzset()


def main() -> None:
    settings = get_settings()
    configure_timezone(settings.app_timezone)
    configure_logging(settings.app_timezone)
    init_db()
    logging.info("AD sync loop started; interval=%s seconds", settings.sync_interval_seconds)
    while True:
        with SessionLocal() as db:
            event = run_sync(db)
            logging.info(
                "sync status=%s seen=%s created=%s updated=%s deleted=%s message=%s",
                event.status,
                event.seen_computers,
                event.created_rows,
                event.updated_rows,
                event.deleted_rows,
                event.message,
            )
        time.sleep(settings.sync_interval_seconds)


if __name__ == "__main__":
    main()
