import argparse
from pathlib import Path
import pkg_resources
from shutil import get_terminal_size
import sqlite3
import sys
from typing import List, Optional

from .cve import CVE
from .db import CVEdb, DEFAULT_DB_PATH


CVE_ID_WIDTH: int = 16


def version() -> str:
    return pkg_resources.require("it-depends")[0].version


def print_cve(cve: CVE):
    if sys.stdout.isatty() and sys.stderr.isatty():
        columns = get_terminal_size((80, 20)).columns
        desc_words = cve.description().split(" ")
        lines = [""]
        for word in desc_words:
            if lines[-1]:
                new_line = f"{lines[-1]} {word}"
                if len(new_line) + CVE_ID_WIDTH > columns:
                    new_line = word
                    lines.append("")
            else:
                new_line = word
            lines[-1] = new_line
        cve_id = cve.cve_id
        if len(cve_id) < CVE_ID_WIDTH:
            cve_id = f"{cve_id}{' ' * (CVE_ID_WIDTH - len(cve_id))}"
        print(f"{cve_id}\033[3m{lines[0]}\033[23m")
        for line in lines[1:]:
            print(f"{' ' * CVE_ID_WIDTH}\033[3m{line}\033[23m")
    else:
        print(f"{cve.cve_id}\t{cve.description()}")


def main(argv: Optional[List[str]] = None) -> int:
    if argv is None:
        argv = sys.argv

    parser = argparse.ArgumentParser(description="A Common Vulnerabilities and Exposures (CVE) database")
    parser.add_argument("SEARCH_TERM", type=str, nargs="*", help="search terms to query")
    parser.add_argument("--database", "-db", type=str, nargs="?", default=DEFAULT_DB_PATH,
                        help=f"alternative path to load/store the database (default is {DEFAULT_DB_PATH!s})")
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
                for cve in db.data():
                    print_cve(cve)
            else:
                for cve in db.data().search(*args.SEARCH_TERM):
                    print_cve(cve)
    except KeyboardInterrupt:
        return 1
