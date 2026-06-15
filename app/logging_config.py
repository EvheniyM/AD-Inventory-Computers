import logging
from datetime import datetime
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError


def _load_timezone(timezone_name: str) -> ZoneInfo:
    for candidate in (timezone_name, "Europe/Kyiv", "Europe/Kiev"):
        try:
            return ZoneInfo(candidate)
        except ZoneInfoNotFoundError:
            continue
    return ZoneInfo("UTC")


class TimezoneFormatter(logging.Formatter):
    def __init__(self, fmt: str, timezone_name: str):
        super().__init__(fmt)
        self.timezone = _load_timezone(timezone_name)

    def formatTime(self, record: logging.LogRecord, datefmt: str | None = None) -> str:
        timestamp = datetime.fromtimestamp(record.created, self.timezone)
        if datefmt:
            return timestamp.strftime(datefmt)
        return f"{timestamp:%Y-%m-%d %H:%M:%S},{int(record.msecs):03d}"


def configure_logging(timezone_name: str) -> None:
    handler = logging.StreamHandler()
    handler.setFormatter(TimezoneFormatter("%(asctime)s %(levelname)s %(message)s", timezone_name))

    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(logging.INFO)
