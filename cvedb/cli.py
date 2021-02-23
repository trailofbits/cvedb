import argparse
from pathlib import Path
import sqlite3
import sys
from typing import List, Optional

from .cve import CVE
from .db import CVEdb, DEFAULT_DB_PATH


def print_cve(cve: CVE):
    print(f"{cve.cve_id:16}\033[3m{cve.description()}\033[23m")


def main(argv: Optional[List[str]] = None):
    if argv is None:
        argv = sys.argv

    parser = argparse.ArgumentParser(description="A Common Vulnerabilities and Exposures (CVE) database")
    parser.add_argument("SEARCH_TERM", type=str, nargs="*", help="search terms to query")
    parser.add_argument("--database", "-db", type=str, nargs="?", default=DEFAULT_DB_PATH,
                        help=f"alternative path to load/store the database (default is {DEFAULT_DB_PATH!s})")

    args = parser.parse_args(argv[1:])

    with CVEdb.open(args.database) as db:
        if not args.SEARCH_TERM:
            # just print all of the CVEs
            for cve in db.data():
                print_cve(cve)
        else:
            for cve in db.data().search(*args.SEARCH_TERM):
                print_cve(cve)
