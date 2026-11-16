"""Regression checks for distribution validation and the snapshot download helper."""

from io import BytesIO
import os
from pathlib import Path
import subprocess
import tarfile
from tempfile import TemporaryDirectory
from unittest import TestCase
import zipfile

from scripts.verify_dist import verify

METADATA = b"""Metadata-Version: 2.4
Name: cvedb
Version: 0.0.5
Requires-Python: >=3.11
License-Expression: LGPL-3.0-or-later
License-File: LICENSE
Requires-Dist: cvss==3.6

"""
INFO = "cvedb-0.0.5.dist-info/"
FEED = "cvedb/data/nvdcve-1.1-2002.json.gz"


def project(root: Path) -> dict[str, bytes]:
    files = dict.fromkeys(("README.md", "LICENSE", "uv.lock", "AGENTS.md", "CODEOWNERS"), b"text\n")
    files.update({"cvedb/__init__.py": b"", FEED: b"snapshot", "cvedb/data/README.md": b"NIST\n"})
    files["pyproject.toml"] = b"""[project]
name = "cvedb"
version = "0.0.5"
requires-python = ">=3.11"
license = "LGPL-3.0-or-later"
dependencies = ["cvss==3.6"]
scripts = {cvedb = "cvedb.__main__:main"}
"""
    for name, data in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    return files


def distributions(
    target: Path, source: dict[str, bytes], wheel: dict[str, bytes]
) -> tuple[Path, Path]:
    sdist = target / "cvedb.tar.gz"
    with tarfile.open(sdist, "w:gz") as archive:
        for name, data in source.items():
            member = tarfile.TarInfo(f"cvedb-0.0.5/{name}")
            member.size = len(data)
            archive.addfile(member, BytesIO(data))
    path = target / "cvedb.whl"
    with zipfile.ZipFile(path, "w") as archive:
        for name, data in wheel.items():
            archive.writestr(name, data)
    return sdist, path


class TestDistributions(TestCase):
    def setUp(  # ty: ignore[missing-override-decorator]  # Python 3.11 lacks override.
        self,
    ) -> None:
        self.temporary = TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.target = Path(self.temporary.name)
        self.root = self.target / "source"
        self.source = project(self.root)
        self.source["PKG-INFO"] = METADATA
        self.wheel = {name: data for name, data in self.source.items() if name.startswith("cvedb/")}
        self.wheel.update(
            {
                INFO + "METADATA": METADATA,
                INFO + "licenses/LICENSE": self.source["LICENSE"],
                INFO + "entry_points.txt": b"[console_scripts]\ncvedb = cvedb.__main__:main\n",
            }
        )

    def check(self) -> None:
        verify(*distributions(self.target, self.source, self.wheel), self.root)

    def test_complete_distribution(self) -> None:
        self.check()

    def test_reformatted_source_project(self) -> None:
        self.source["pyproject.toml"] += b"\n# Canonicalized TOML remains equivalent.\n"
        self.check()

    def test_changed_source_project(self) -> None:
        self.source["pyproject.toml"] = self.source["pyproject.toml"].replace(b"0.0.5", b"0.0.6")
        with self.assertRaisesRegex(ValueError, "differs from the source tree"):
            self.check()

    def test_missing_bundled_feed(self) -> None:
        del self.wheel[FEED]
        with self.assertRaisesRegex(ValueError, "missing required files"):
            self.check()

    def test_changed_bundled_feed(self) -> None:
        self.wheel[FEED] = b"changed"
        with self.assertRaisesRegex(ValueError, "differs from the source tree"):
            self.check()

    def test_missing_source_document(self) -> None:
        del self.source["AGENTS.md"]
        with self.assertRaisesRegex(ValueError, "missing required files"):
            self.check()

    def test_cached_files(self) -> None:
        for contents in (self.source, self.wheel):
            with self.subTest(contents=contents is self.source):
                contents["cvedb/__pycache__/cached.pyc"] = b"cache"
                with self.assertRaisesRegex(ValueError, "generated or cached"):
                    self.check()
                del contents["cvedb/__pycache__/cached.pyc"]

    def test_invalid_metadata(self) -> None:
        fields = (
            b"Name: cvedb",
            b"Version: 0.0.5",
            b"Requires-Python: >=3.11",
            b"License-Expression: LGPL-3.0-or-later",
            b"License-File: LICENSE",
            b"Requires-Dist: cvss==3.6",
        )
        for field in fields:
            with self.subTest(field=field):
                self.wheel[INFO + "METADATA"] = METADATA.replace(field, field + b"-wrong")
                with self.assertRaises(ValueError):
                    self.check()

    def test_wrong_license(self) -> None:
        self.wheel[INFO + "licenses/LICENSE"] = b"wrong"
        with self.assertRaisesRegex(ValueError, "project license"):
            self.check()

    def test_wrong_entry_point(self) -> None:
        self.wheel[INFO + "entry_points.txt"] = b"[console_scripts]\ncvedb = wrong:main\n"
        with self.assertRaisesRegex(ValueError, "console scripts"):
            self.check()

    def test_missing_metadata_files(self) -> None:
        for contents, name in (
            (self.source, "PKG-INFO"),
            (self.wheel, INFO + "METADATA"),
            (self.wheel, INFO + "entry_points.txt"),
        ):
            with self.subTest(name=name):
                data = contents.pop(name)
                with self.assertRaisesRegex(ValueError, "missing required metadata file"):
                    self.check()
                contents[name] = data

    def test_missing_console_scripts(self) -> None:
        self.wheel[INFO + "entry_points.txt"] = b"[unrelated]\nvalue = other\n"
        with self.assertRaisesRegex(ValueError, "console scripts"):
            self.check()

    def test_unrelated_wheel_content(self) -> None:
        self.wheel["test/leftover.py"] = b""
        with self.assertRaisesRegex(ValueError, "outside the package"):
            self.check()


class TestSnapshotDownload(TestCase):
    def run_helper(self, date_status: int = 0, wget_status: int = 0) -> tuple[int, list[str]]:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            log = root / "requests"
            for name, text in {
                "date": f"#!/usr/bin/env bash\nprintf '2003\\n'\nexit {date_status}\n",
                "wget": f'#!/usr/bin/env bash\nprintf "%s\\n" "$*" >> "$WGET_LOG"\n'
                f"exit {wget_status}\n",
            }.items():
                command = root / name
                command.write_text(text)
                command.chmod(0o755)
            script = Path(__file__).resolve().parent.parent / "cvedb" / "data" / "download.sh"
            result = subprocess.run(
                ["bash", str(script)],
                cwd=root,
                check=False,
                env={
                    **os.environ,
                    "PATH": f"{root}{os.pathsep}{os.environ['PATH']}",
                    "WGET_LOG": str(log),
                },
            )
            return result.returncode, log.read_text().splitlines() if log.exists() else []

    def test_downloads_matching_current_feed_pairs(self) -> None:
        status, requests = self.run_helper()
        base = "-N https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-"
        self.assertEqual(status, 0)
        self.assertEqual(
            requests,
            [
                base + str(year) + suffix
                for year in (2003, 2002)
                for suffix in (".meta", ".json.gz")
            ],
        )

    def test_failed_download_stops_immediately(self) -> None:
        status, requests = self.run_helper(wget_status=3)
        self.assertEqual(status, 3)
        self.assertEqual(len(requests), 1)

    def test_failed_date_prevents_downloads(self) -> None:
        self.assertEqual(self.run_helper(date_status=7), (7, []))
