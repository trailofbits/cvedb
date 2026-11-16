"""Exercise locked audits with the real tools and mocked advisory HTTP responses."""

import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
from unittest import TestCase
from unittest.mock import patch

from scripts.audit_dependencies import audit

HTTP_FIXTURE = r"""
import json
import os
from pathlib import Path
import sys
from unittest.mock import patch

import requests


def response(session, request, **kwargs):
    if "-r" not in sys.argv:
        raise AssertionError("Unexpected advisory request outside pip-audit")
    requirements = Path(sys.argv[sys.argv.index("-r") + 1])
    record = Path(os.environ["AUDIT_TEST_RECORD"])
    record.write_text(str(requirements) + "\n" + requirements.read_text())
    mode = os.environ["AUDIT_TEST_MODE"]
    if mode == "outage":
        raise requests.ConnectTimeout("Simulated PyPI outage")
    result = requests.Response()
    result.url = request.url
    result.request = request
    result.status_code = 404 if mode == "missing" else 200
    vulnerabilities = []
    if mode == "advisory" and "/cvss/" in request.url:
        vulnerabilities.append({
            "id": "PYSEC-2099-1", "aliases": [], "fixed_in": [],
            "details": "Test advisory response",
        })
    result._content = json.dumps({"vulnerabilities": vulnerabilities}).encode()
    return result


patch("requests.sessions.Session.send", response).start()
"""


class TestDependencyAudit(TestCase):
    def run_audit(self, mode: str) -> tuple[subprocess.CompletedProcess[str], str]:
        with TemporaryDirectory() as directory:
            target = Path(directory)
            (target / "sitecustomize.py").write_text(HTTP_FIXTURE)
            record = target / "export-record.txt"
            root = Path(__file__).resolve().parent.parent
            result = subprocess.run(
                [sys.executable, "-m", "scripts.audit_dependencies"],
                cwd=root,
                env={
                    **os.environ,
                    "PYTHONPATH": str(target),
                    "AUDIT_TEST_MODE": mode,
                    "AUDIT_TEST_RECORD": str(record),
                    "UV_OFFLINE": "true",
                },
                text=True,
                capture_output=True,
                check=False,
                timeout=30,
            )
            self.assertTrue(record.exists(), result.stderr)
            contents = record.read_text()
            requirements, exported = contents.split("\n", 1)
            self.assertFalse(Path(requirements).parent.exists())
            return result, exported

    def test_audits_locked_runtime_and_development_packages(self) -> None:
        result, exported = self.run_audit("clean")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("No known vulnerabilities found", result.stderr)
        self.assertIn("cvss==", exported)
        self.assertIn("pip-audit==", exported)
        self.assertIn("--hash=sha256:", exported)
        self.assertNotIn("-e .", exported)
        self.assertNotIn("cvedb==", exported)
        self.assertNotIn("WARNING", result.stderr)

    def test_advisory_fails_and_removes_temporary_export(self) -> None:
        result, _ = self.run_audit("advisory")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("PYSEC-2099-1", result.stdout)
        self.assertIn("Dependency vulnerability audit failed", result.stderr)

    def test_service_failure_fails_and_removes_temporary_export(self) -> None:
        result, _ = self.run_audit("outage")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("Could not connect to PyPI", result.stderr)
        self.assertIn("Dependency vulnerability audit failed", result.stderr)

    def test_unauditable_dependency_fails(self) -> None:
        result, _ = self.run_audit("missing")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("Dependency not found on PyPI", result.stderr)

    def test_lock_failure_identifies_the_operation(self) -> None:
        with TemporaryDirectory() as directory:
            with self.assertRaisesRegex(RuntimeError, "Dependency lock validation failed"):
                audit(Path(directory))

    def test_missing_tool_identifies_the_operation(self) -> None:
        with TemporaryDirectory() as directory, patch.dict(os.environ, {"PATH": ""}):
            with self.assertRaisesRegex(RuntimeError, "Dependency lock validation failed"):
                audit(Path(directory))
