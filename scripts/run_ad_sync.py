from app.db import SessionLocal
from app.sync_service import run_sync


def main() -> None:
    with SessionLocal() as db:
        event = run_sync(db, include_discovery=False)
        print(
            f"status={event.status} seen={event.seen_computers} "
            f"created={event.created_rows} updated={event.updated_rows} "
            f"deleted={event.deleted_rows} message={event.message}"
        )


if __name__ == "__main__":
    main()
