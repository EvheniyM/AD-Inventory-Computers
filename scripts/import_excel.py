import argparse

from app.db import SessionLocal, init_db
from app.excel_service import import_workbook


def main() -> None:
    parser = argparse.ArgumentParser(description="Import BARS T18 XLSX into PostgreSQL")
    parser.add_argument("xlsx_path")
    args = parser.parse_args()

    init_db()
    with SessionLocal() as db:
        count = import_workbook(args.xlsx_path, db)
    print(f"Imported rows: {count}")


if __name__ == "__main__":
    main()

