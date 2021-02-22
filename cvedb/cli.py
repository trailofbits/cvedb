import argparse
from pathlib import Path
import sqlite3
import sys
from typing import List, Optional


from .db import CVEdb


def main(argv: Optional[List[str]] = None):
    if argv is None:
        argv = sys.argv

    default_db_path = Path.home() / ".config" / "cvedb" / "cvedb.sqlite"

    parser = argparse.ArgumentParser(description="A Common Vulnerabilities and Exposures (CVE) database")
    parser.add_argument("SEARCH_TERM", type=str, nargs="*", help="search terms to query")
    parser.add_argument("--database", "-db", type=str, nargs="?", default=default_db_path,
                        help=f"alternative path to load/store the database (default is {default_db_path!s})")

    args = parser.parse_args(argv)

    with CVEdb.open(args.database) as db:
        for term in args.SEARCH_TERM:
            pass

        for cve in db.data():
            print(cve)
