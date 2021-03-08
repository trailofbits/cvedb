import argparse
from datetime import datetime
from dateutil.parser import isoparse, ParserError
import pkg_resources
import sys
from typing import List, Optional, Union

from .cpe import Logical
from .db import CVEdb, DEFAULT_DB_PATH
from .feed import Data
from .printing import print_cves
from .search import (
    AfterModifiedDateQuery, AfterPublishedDateQuery, AndQuery, BeforeModifiedDateQuery, BeforePublishedDateQuery,
    CPEQuery, Sort
)


def version() -> str:
    return pkg_resources.require("cvedb")[0].version


def parse_date(date_str: str) -> datetime:
    try:
        return isoparse(date_str).astimezone()
    except ParserError:
        pass
    raise argparse.ArgumentTypeError(f"Invalid date {date_str!r}. Dates must be either a four digit year or an ISO "
                                     "8601 string. See https://dateutil.readthedocs.io/en/stable/parser.html "
                                     "for examples.")


def parse_cpe_arg(cpe_str: str) -> Union[Logical, str]:
    for logical in Logical:
        if logical.value == cpe_str:
            return logical
    return cpe_str


def main(argv: Optional[List[str]] = None) -> int:
    if argv is None:
        argv = sys.argv

    parser = argparse.ArgumentParser(description="A Common Vulnerabilities and Exposures (CVE) database")
    parser.add_argument("SEARCH_TERM", type=str, nargs="*", help="search terms to query")
    parser.add_argument("--database", "-db", type=str, nargs="?", default=DEFAULT_DB_PATH,
                        help=f"alternative path to load/store the database (default is {DEFAULT_DB_PATH!s})")
    parser.add_argument("--sort", "-s", nargs="*", default=("cve",),
                        choices=("cve", "modified", "published", "impact", "severity"),
                        help="how to sort the results (default is by CVE ID only)")
    parser.add_argument("--descending", "-d", action="store_true",
                        help="reverse the ordering of results (default is ascending)")
    parser.add_argument("--after", "-a", type=parse_date, help="only list CVEs published after the given date")
    parser.add_argument("--before", "-b", type=parse_date, help="only list CVEs published before the given date")
    parser.add_argument("--modified-after", "-ma", type=parse_date, help="only list CVEs modified after the given date")
    parser.add_argument("--modified-before", "-mb", type=parse_date,
                        help="only list CVEs modified before the given date")

    cpe_group = parser.add_argument_group(title="Common Platform Enumeration (CPE)",
                                          description="search options filtering by CPE")
    cpe_group.add_argument("--vendor", type=parse_cpe_arg, nargs="?", default=Logical.ANY,
                           help="search by software/hardware vendor")
    cpe_group.add_argument("--software-version", type=parse_cpe_arg, nargs="?", default=Logical.ANY,
                           help="search by version")

    parser.add_argument("--ansi", action="store_true", help="force ANSI colored output even when not printing to a TTY "
                                                            "(e.g., when piping output to a file or pager)")

    parser.add_argument("--version", "-v", action="store_true", help="print the version and exit")

    args = parser.parse_args(argv[1:])

    if args.version:
        if sys.stdout.isatty():
            print(f"cvedb version {version()}")
        else:
            print(version())
        return 0

    query = []
    if args.after:
        query.append(AfterPublishedDateQuery(args.after))
    if args.before:
        query.append(BeforePublishedDateQuery(args.before))
    if args.modified_before:
        query.append(BeforeModifiedDateQuery(args.modified_before))
    if args.modified_after:
        query.append(AfterModifiedDateQuery(args.modified_after))
    if args.SEARCH_TERM:
        query.append(Data.make_query(*args.SEARCH_TERM))

    if args.software_version != Logical.ANY or args.vendor != Logical.ANY:
        cpe = CPEQuery(
            vendor=args.vendor,
            version=args.software_version
        )
        query.append(cpe)
    if len(query) == 1:
        query = query[0]
    elif query:
        query = AndQuery(*query)
    else:
        query = None

    try:
        with CVEdb.open(args.database) as db:
            if query is None:
                # just print all of the CVEs
                print_cves(db.data())
            else:
                sorts = []
                for sort in args.sort:
                    if sort == "cve":
                        sorts.append(Sort.CVE_ID)
                    elif sort == "modified":
                        sorts.append(Sort.LAST_MODIFIED_DATE)
                    elif sort == "published":
                        sorts.append(Sort.PUBLISHED_DATE)
                    elif sort == "impact":
                        sorts.append(Sort.IMPACT)
                    elif sort == "severity":
                        sorts.append(Sort.SEVERITY)
                if args.ansi:
                    force_ansi = True
                else:
                    force_ansi = None
                print_cves(
                    db.data().search(query, sort=sorts, ascending=not args.descending),
                    force_color=force_ansi
                )
    except (KeyboardInterrupt, BrokenPipeError):
        return 1
