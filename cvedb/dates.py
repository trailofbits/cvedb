"""UTC instant and CLI date-boundary policies."""

import argparse
from datetime import datetime, timezone
import re
from typing import cast

from dateutil.parser import isoparse

_DATE_ONLY = re.compile(r"[0-9]{4}(?:-[0-9]{2}(?:-[0-9]{2})?|[0-9]{4}|-?W[0-9]{2}(?:-?[0-9])?)?")


def utc_datetime(value: datetime) -> datetime:
    """Return an aware UTC instant, interpreting a naive value as UTC."""
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def parse_date(value: str) -> datetime:
    """Parse an ISO date or timestamp as an aware UTC instant.

    Missing month and day components denote the first day of the parsed period.
    Date-only values start at midnight. Naive timestamps are interpreted as UTC.

    Raises:
        argparse.ArgumentTypeError: The value is not a supported ISO date or timestamp.
    """
    try:
        return utc_datetime(cast(datetime, isoparse(value)))
    except (ValueError, OverflowError) as error:
        raise argparse.ArgumentTypeError(
            f"Invalid date {value!r}. Use a four-digit year or an ISO 8601 date or timestamp."
        ) from error


def parse_before_date(value: str) -> datetime:
    """Parse an inclusive before bound, including a date-only value's whole UTC day.

    Explicit timestamps retain their exact instant, including midnight. Year-only
    and month-only forms refer to their parsed first day, rather than a whole year
    or month.
    """
    parsed = parse_date(value)
    if _DATE_ONLY.fullmatch(value):
        return parsed.replace(hour=23, minute=59, second=59, microsecond=999999)
    return parsed
