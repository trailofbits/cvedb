"""Date-boundary policy for CLI filters and public queries."""

import argparse
from datetime import datetime, UTC
from unittest.mock import MagicMock, patch

import pytest

from cvedb import cli
from cvedb.cve import CVE
from cvedb.dates import parse_before_date, parse_date, utc_datetime
from cvedb.search import SearchQuery


@pytest.mark.parametrize(
    ("value", "day"),
    [
        ("2020", datetime(2020, 1, 1)),
        ("2020-02", datetime(2020, 2, 1)),
        ("2020-02-03", datetime(2020, 2, 3)),
        ("20200203", datetime(2020, 2, 3)),
        ("2020-W01", datetime(2019, 12, 30)),
        ("2020W01", datetime(2019, 12, 30)),
        ("2020-W01-3", datetime(2020, 1, 1)),
        ("2020W013", datetime(2020, 1, 1)),
        ("2020-02-29", datetime(2020, 2, 29)),
        ("9999-12-31", datetime(9999, 12, 31)),
    ],
)
def test_date_only_bounds_use_the_parsed_utc_day(value: str, day: datetime) -> None:
    assert parse_date(value) == day.replace(tzinfo=UTC)
    assert parse_before_date(value) == day.replace(
        hour=23, minute=59, second=59, microsecond=999999, tzinfo=UTC
    )


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("2020-01-02T00:00:00Z", datetime(2020, 1, 2, tzinfo=UTC)),
        ("2020-01-02 00:00:00", datetime(2020, 1, 2, tzinfo=UTC)),
        ("2020-01-02T03:00:00+03:00", datetime(2020, 1, 2, tzinfo=UTC)),
        ("2020-01-01T24:00:00Z", datetime(2020, 1, 2, tzinfo=UTC)),
        ("20200102T000000", datetime(2020, 1, 2, tzinfo=UTC)),
        (
            "2020-01-02T00:00:00.123456Z",
            datetime(2020, 1, 2, microsecond=123456, tzinfo=UTC),
        ),
    ],
)
def test_explicit_timestamps_keep_their_exact_inclusive_instant(
    value: str, expected: datetime
) -> None:
    assert parse_date(value) == expected
    assert parse_before_date(value) == expected


@pytest.mark.parametrize(
    "value", ["", "invalid", "2020-13-01", "2020-02-30", "2020-W99", "10000-01-01"]
)
@pytest.mark.parametrize("parser", [parse_date, parse_before_date])
def test_invalid_dates_produce_actionable_argument_errors(value: str, parser: object) -> None:
    assert callable(parser)
    with pytest.raises(argparse.ArgumentTypeError, match="Invalid date.*ISO 8601"):
        parser(value)


def test_naive_dates_are_utc_without_consulting_the_machine_timezone() -> None:
    value = datetime(2020, 1, 2, 3, 4, 5)
    assert utc_datetime(value) == value.replace(tzinfo=UTC)
    assert parse_date("2020-01-02T03:04:05") == value.replace(tzinfo=UTC)


@pytest.mark.parametrize("flag", ["--before", "--modified-before", "--after", "--modified-after"])
def test_cli_date_only_filters_apply_the_documented_boundary(flag: str) -> None:
    db = MagicMock()
    with (
        patch("cvedb.cli.CVEdb.open") as open_db,
        patch("cvedb.cli.print_cves"),
    ):
        open_db.return_value.__enter__.return_value = db
        cli.main(["cvedb", flag, "2020-01-02"])
    query = db.data.return_value.search.call_args.args[0]
    assert isinstance(query, SearchQuery)
    noon = datetime(2020, 1, 2, 12, tzinfo=UTC)
    assert query.matches(CVE("CVE-1", noon, noon))
    later = datetime(2020, 1, 3, tzinfo=UTC)
    assert query.matches(CVE("CVE-1", later, later)) == ("after" in flag)


def test_cli_explicit_midnight_does_not_become_the_end_of_the_day() -> None:
    db = MagicMock()
    with patch("cvedb.cli.CVEdb.open") as open_db, patch("cvedb.cli.print_cves"):
        open_db.return_value.__enter__.return_value = db
        cli.main(["cvedb", "--before", "2020-01-02T00:00:00Z"])
    query = db.data.return_value.search.call_args.args[0]
    assert isinstance(query, SearchQuery)
    noon = datetime(2020, 1, 2, 12, tzinfo=UTC)
    assert not query.matches(CVE("CVE-1", noon, noon))
