import argparse
import sys
from typing import List, Optional

from .nvd import JsonFeed


def main(argv: Optional[List[str]] = None):
    if argv is None:
        argv = sys.argv

    parser = argparse.ArgumentParser(description="A Common Vulnerabilities and Exposures (CVE) database")
    parser.add_argument("SEARCH_TERM", type=str, nargs="*", help="search terms to query")

    args = parser.parse_args(argv)

    for term in args.SEARCH_TERM:
        pass

    print(JsonFeed("2021").data())
