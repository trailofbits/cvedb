import argparse
from pathlib import Path
import pkg_resources
from shutil import get_terminal_size
import sqlite3
import sys
from typing import List, Optional

from .cve import CVE, Severity
from .db import CVEdb, DEFAULT_DB_PATH
from .search import Sort


CVE_ID_WIDTH: int = 17


def version() -> str:
    return pkg_resources.require("it-depends")[0].version


SEVERITY_COLORS = {
    Severity.UNKNOWN:  "\033[34;1m",  # Blue
    Severity.NONE:     "\033[37;1m",  # White
    Severity.LOW:      "\033[36;1m",  # Cyan
    Severity.MEDIUM:   "\033[33;1m",  # Yellow
    Severity.HIGH:     "\033[31;1m",  # Red
    Severity.CRITICAL: "\033[35;1m"   # Magenta
}

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
        color = SEVERITY_COLORS[cve.severity]
        print(f"{color}{cve_id}\033[0m\033[3m{lines[0]}\033[23m")
        if len(lines) < 3:
            lines += [""] * (3 - len(lines))
        for i, line in enumerate(lines[1:]):
            if i == 0:
                prefix = cve.severity.name
            elif i == 1 and cve.impact is not None:
                prefix = f"Impact: {cve.impact.base_score:.1f}"
            else:
                prefix = " " * CVE_ID_WIDTH
            if len(prefix) < CVE_ID_WIDTH:
                prefix += " " * (CVE_ID_WIDTH - len(prefix))
            print(f"{color}{prefix}\033[0m\033[3m{line}\033[23m")
        print()
    else:
        print(f"{cve.cve_id}\t{cve.description()}")


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
                for cve in db.data().search(*args.SEARCH_TERM, sort=sorts, ascending=not args.descending):
                    print_cve(cve)
    except (KeyboardInterrupt, BrokenPipeError):
        return 1
