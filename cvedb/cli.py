"""Command-line operations for local searches and explicit upstream updates."""

import argparse
from collections.abc import Generator, Iterator, Sequence
from contextlib import ExitStack, contextmanager
from datetime import datetime
from importlib.metadata import version as package_version
from pathlib import Path
from sqlite3 import Error as SQLiteError
import sys

from cvedb.cpe import Logical
from cvedb.cve import CVE
from cvedb.dates import parse_before_date, parse_date, utc_datetime
from cvedb.db import CVEdb, DEFAULT_DB_PATH
from cvedb.feed import Data
from cvedb.nvd import JsonFeed
from cvedb.printing import print_cves
from cvedb.search import (
    AfterModifiedDateQuery,
    AfterPublishedDateQuery,
    AndQuery,
    BeforeModifiedDateQuery,
    BeforePublishedDateQuery,
    CPEQuery,
    SearchQuery,
    Sort,
    TermQuery,
)

_SORTS = {
    "cve": Sort.CVE_ID,
    "modified": Sort.LAST_MODIFIED_DATE,
    "published": Sort.PUBLISHED_DATE,
    "impact": Sort.IMPACT,
    "severity": Sort.SEVERITY,
}


class _Arguments(argparse.Namespace):
    search_terms: list[str]
    update: bool
    database: str | Path
    sort: Sequence[str]
    descending: bool
    after: datetime | None
    before: datetime | None
    modified_after: datetime | None
    modified_before: datetime | None
    vendor: Logical | str | None
    software_version: Logical | str | None
    ansi: bool
    version: bool
    data_version: bool


class _OperationError(Exception):
    """An expected command failure with operation and database context."""


def version() -> str:
    """Return the installed CVEdb package version."""
    return package_version("cvedb")


def parse_cpe_arg(value: str) -> Logical | str:
    """Parse logical ANY/NA values, retaining other CPE attribute strings."""
    for logical in Logical:
        if logical.value == value:
            return logical
    return value


def _add_general_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "search_terms", metavar="SEARCH_TERM", nargs="*", help="search terms to query"
    )
    parser.add_argument(
        "--update",
        "-u",
        action="store_true",
        help="update the database to the latest version; requires Internet access",
    )
    parser.add_argument(
        "--database",
        "-db",
        default=DEFAULT_DB_PATH,
        help=f"database path (default: {DEFAULT_DB_PATH!s})",
    )
    parser.add_argument(
        "--sort",
        "-s",
        nargs="*",
        default=("cve",),
        choices=tuple(_SORTS),
        help="how to sort results (default: CVE ID)",
    )
    parser.add_argument("--descending", "-d", action="store_true", help="sort in descending order")
    parser.add_argument(
        "--ansi", action="store_true", help="force ANSI output, including piped output"
    )
    parser.add_argument("--version", "-v", action="store_true", help="print the version and exit")
    parser.add_argument(
        "--data-version",
        "-dv",
        action="store_true",
        help="report installed bundles and stored feed versions, then exit",
    )


def _add_date_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--after",
        "-a",
        type=parse_date,
        help="list CVEs published at or after this UTC date or timestamp",
    )
    parser.add_argument(
        "--before",
        "-b",
        type=parse_before_date,
        help="list CVEs published through this UTC date or timestamp",
    )
    parser.add_argument(
        "--modified-after",
        "-ma",
        type=parse_date,
        help="list CVEs modified at or after this UTC date or timestamp",
    )
    parser.add_argument(
        "--modified-before",
        "-mb",
        type=parse_before_date,
        help="list CVEs modified through this UTC date or timestamp",
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="A Common Vulnerabilities and Exposures (CVE) database"
    )
    _add_general_arguments(parser)
    _add_date_arguments(parser)
    cpe = parser.add_argument_group("Common Platform Enumeration (CPE)")
    cpe.add_argument("--vendor", type=parse_cpe_arg, help="search by software/hardware vendor")
    cpe.add_argument("--software-version", type=parse_cpe_arg, help="search by version")
    return parser


def _query(args: _Arguments) -> SearchQuery | None:
    dates = (
        (args.after, AfterPublishedDateQuery),
        (args.before, BeforePublishedDateQuery),
        (args.modified_before, BeforeModifiedDateQuery),
        (args.modified_after, AfterModifiedDateQuery),
    )
    queries: list[SearchQuery] = [factory(value) for value, factory in dates if value is not None]
    if args.search_terms:
        queries.append(Data.make_query(*args.search_terms))
    if args.vendor is not None or args.software_version is not None:
        queries.append(
            CPEQuery(
                vendor=Logical.ANY if args.vendor is None else args.vendor,
                version=Logical.ANY if args.software_version is None else args.software_version,
            )
        )
    if not queries:
        return None
    return queries[0] if len(queries) == 1 else AndQuery(*queries)


@contextmanager
def _database(path: str | Path) -> Generator[CVEdb, None, None]:
    with ExitStack() as stack:
        try:
            database = stack.enter_context(CVEdb.open(path))
        except (OSError, SQLiteError, ValueError) as error:
            raise _OperationError(f"Cannot open database {path!s}: {error}") from error
        yield database


def _update(path: str | Path) -> None:
    try:
        with _database(path) as database:
            database.reload(force=True)
    except (BrokenPipeError, KeyboardInterrupt):
        raise
    except (OSError, SQLiteError, ValueError, NotImplementedError) as error:
        raise _OperationError(f"Cannot update database {path!s}: {error}") from error


def _date_label(value: datetime | None, missing: str = "never") -> str:
    return missing if value is None else utc_datetime(value).strftime("%Y-%m-%d")


def _data_version_table(db: CVEdb) -> tuple[list[list[str]], str]:
    rows = [["Feed", "Bundled date", "Stored modified", "Last checked", "Stored CVEs"]]
    bundles: list[tuple[str, datetime]] = []
    for feed in db.feeds:
        metadata = feed.parent._installed_meta() if isinstance(feed.parent, JsonFeed) else None
        if metadata is not None:
            bundles.append((feed.name, metadata.last_modified_date))
        bundled = _date_label(None if metadata is None else metadata.last_modified_date, "none")
        count = db.connection.execute(
            "SELECT COUNT(*) FROM cves WHERE feed=?", (feed.feed_id,)
        ).fetchone()[0]
        rows.append(
            [
                feed.name,
                bundled,
                _date_label(feed.last_modified()),
                _date_label(feed.last_checked()),
                str(count),
            ]
        )
    summary = "Installed bundles for selected feeds: none"
    if bundles:
        names = ", ".join(name for name, _ in bundles)
        newest = max(date for _, date in bundles)
        summary = (
            f"Installed bundles for selected feeds: {names}; latest metadata: {_date_label(newest)}"
        )
    return rows, summary


def _print_table(rows: list[list[str]], path: str | Path) -> None:
    widths = [max(len(row[index]) for row in rows) for index in range(len(rows[0]))]
    width = sum(widths) + len(widths) + 1
    border = f"+{'=' * (width - 2)}+\n"
    heading = f"Database: {path!s}"
    if len(heading) > width - 2:
        heading = heading[: width - 5] + "..."
    sys.stdout.write(border + "|" + heading.center(width - 2) + "|\n" + border)
    for index, row in enumerate(rows):
        sys.stdout.write(
            "|" + "|".join(value.ljust(size) for value, size in zip(row, widths)) + "|\n"
        )
        if index == 0:
            sys.stdout.write(border)
    sys.stdout.write(border)


def _report(path: str | Path) -> None:
    try:
        with _database(path) as database:
            rows, summary = _data_version_table(database)
            sys.stdout.write(summary + "\n")
            _print_table(rows, path)
    except (BrokenPipeError, KeyboardInterrupt):
        raise
    except (OSError, SQLiteError, ValueError) as error:
        raise _OperationError(f"Cannot report database {path!s}: {error}") from error


def _listing_results(results: Iterator[CVE], path: str | Path) -> Generator[CVE, None, None]:
    try:
        yield from results
    except ValueError as error:
        raise _OperationError(f"Cannot list database {path!s}: {error}") from error
    finally:
        if isinstance(results, Generator):
            results.close()


def _list(args: _Arguments, query: SearchQuery) -> None:
    try:
        with _database(args.database) as database:
            try:
                results = database.data().search(
                    query,
                    sort=[_SORTS[value] for value in args.sort],
                    ascending=not args.descending,
                )
            except ValueError as error:
                raise _OperationError(f"Cannot list database {args.database!s}: {error}") from error
            guarded = _listing_results(results, args.database)
            try:
                print_cves(guarded, force_color=True if args.ansi else None)
            finally:
                guarded.close()
    except (BrokenPipeError, KeyboardInterrupt):
        raise
    except (OSError, SQLiteError) as error:
        raise _OperationError(f"Cannot list database {args.database!s}: {error}") from error


def _run(args: _Arguments) -> int:
    if args.update:
        _update(args.database)
    if args.version:
        value = version()
        print(f"cvedb version {value}" if sys.stdout.isatty() else value)
        return 0
    if args.data_version:
        _report(args.database)
        return 0
    query = _query(args)
    if args.update and query is None:
        return 0
    _list(args, TermQuery("") if query is None else query)
    return 0


def main(argv: list[str] | None = None) -> int:
    """Execute CLI arguments including the program name, or use sys.argv.

    Return 0 for success and 1 for expected operation failures, interrupted output,
    or cancellation. Argparse retains its usage/help SystemExit behavior. Updates
    commit before a separate listing/report context begins.
    """
    try:
        args = _parser().parse_args(
            (sys.argv if argv is None else argv)[1:], namespace=_Arguments()
        )
        return _run(args)
    except (KeyboardInterrupt, BrokenPipeError):
        return 1
    except _OperationError as error:
        try:
            print(f"cvedb: {error}", file=sys.stderr)
        except (KeyboardInterrupt, BrokenPipeError):
            return 1
        return 1
