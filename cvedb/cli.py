import argparse
from pathlib import Path
import sqlite3
import sys
from typing import List, Optional

from .db import CVEdb, DEFAULT_DB_PATH


def main(argv: Optional[List[str]] = None):
    if argv is None:
        argv = sys.argv

    parser = argparse.ArgumentParser(description="A Common Vulnerabilities and Exposures (CVE) database")
    parser.add_argument("SEARCH_TERM", type=str, nargs="*", help="search terms to query")
    parser.add_argument("--database", "-db", type=str, nargs="?", default=DEFAULT_DB_PATH,
                        help=f"alternative path to load/store the database (default is {DEFAULT_DB_PATH!s})")

    args = parser.parse_args(argv)

    with CVEdb.open(args.database) as db:
        for term in args.SEARCH_TERM:
            pass

        for cve in db.data():
            print(cve)
