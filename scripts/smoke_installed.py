"""Exercise the installed wheel with network access disabled."""

from importlib.metadata import distribution
from pathlib import Path
import socket
from tempfile import TemporaryDirectory
from unittest.mock import patch

import cvedb
from cvedb.cpe import CPE
from cvedb.db import CVEdb
from cvedb.feed import FEEDS


def main() -> None:
    """Verify installed imports, data, CPE parsing, and an isolated offline database."""
    source = Path(__file__).resolve().parent.parent
    installed = Path(cvedb.__file__).resolve()
    if installed.is_relative_to(source):
        raise ValueError(f"Smoke test imported the source tree instead of the wheel: {installed}")
    if not installed.with_name("py.typed").is_file():
        raise ValueError("Installed wheel has no py.typed marker")
    if not any(entry.name == "cvedb" for entry in distribution("cvedb").entry_points):
        raise ValueError("Installed wheel has no cvedb entry point")
    cpe = CPE(vendor="example", product="widget")
    if CPE.loads(cpe.dumps()) != cpe:
        raise ValueError("Installed CPE serialization failed")
    with (
        TemporaryDirectory() as directory,
        patch.object(
            socket,
            "socket",
            side_effect=AssertionError("Offline smoke test attempted network access"),
        ),
    ):
        with CVEdb.open(Path(directory) / "offline.sqlite", parents=[FEEDS["2002"]]) as db:
            records = db.data()
            if len(records) == 0:
                raise ValueError("Installed 2002 snapshot did not initialize offline")
            first = next(iter(records))
            if not any(record.cve_id == first.cve_id for record in records.search(first.cve_id)):
                raise ValueError("Installed offline database query did not find its stored record")


if __name__ == "__main__":
    main()
