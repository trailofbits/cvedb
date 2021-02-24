import argparse
import pkg_resources
import sys
from typing import List, Optional

from .db import CVEdb, DEFAULT_DB_PATH
from .printing import print_cves
from .search import Sort


def version() -> str:
    return pkg_resources.require("it-depends")[0].version


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
    parser.add_argument("--ansi", "-a", action="store_true", help="force ANSI colored output even when not printing to "
                                                                  "a TTY (e.g., when piping output to a file or pager)")
    parser.add_argument("--version", "-v", action="store_true", help="print the version and exit")

    args = parser.parse_args(argv[1:])

    if args.version:
        if sys.stdout.isatty():
            print(f"cvedb version {version()}")
        else:
            print(version())
        return 0

    try:
        with CVEdb.open(args.database) as db:
            if not args.SEARCH_TERM:
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
                    db.data().search(*args.SEARCH_TERM, sort=sorts, ascending=not args.descending),
                    force_color=force_ansi
                )
    except (KeyboardInterrupt, BrokenPipeError):
        return 1
