"""Validate release identity against real tags and Git ancestry in isolated repositories."""

from contextlib import redirect_stderr
from io import StringIO
import json
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
from unittest import TestCase
from unittest.mock import patch

from scripts.verify_release import main, verify_release


def git(root: Path, *arguments: str) -> str:
    result = subprocess.run(
        [
            "git",
            "-c",
            "user.name=Release Test",
            "-c",
            "user.email=release@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "-c",
            "core.hooksPath=/dev/null",
            *arguments,
        ],
        cwd=root,
        capture_output=True,
        check=True,
        text=True,
        env={key: value for key, value in os.environ.items() if not key.startswith("GIT_")},
    )
    return result.stdout.strip()


def event(tag: str = "v0.0.5", branch: str = "main") -> dict[str, object]:
    return {
        "action": "published",
        "release": {"draft": False, "tag_name": tag},
        "repository": {"default_branch": branch},
    }


class TestRelease(TestCase):
    def setUp(  # ty: ignore[missing-override-decorator]  # Python 3.11 lacks override.
        self,
    ) -> None:
        environment = {
            key: value for key, value in os.environ.items() if not key.startswith("GIT_")
        }
        clean = patch.dict(os.environ, environment, clear=True)
        clean.start()
        self.addCleanup(clean.stop)
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        git(self.root, "init", "--initial-branch", "main")
        (self.root / "pyproject.toml").write_text('[project]\nversion = "0.0.5"\n')
        git(self.root, "add", "pyproject.toml")
        git(self.root, "commit", "-m", "Initial version")
        self.sha = git(self.root, "rev-parse", "HEAD")
        git(self.root, "update-ref", "refs/remotes/origin/main", self.sha)

    def verify(self, payload: object | None = None, sha: str | None = None) -> None:
        verify_release(
            self.root,
            event() if payload is None else payload,
            "release",
            self.sha if sha is None else sha,
            "refs/tags/v0.0.5",
        )

    def test_lightweight_tag(self) -> None:
        git(self.root, "tag", "v0.0.5")
        self.verify()

    def test_annotated_tag(self) -> None:
        git(self.root, "tag", "--annotate", "v0.0.5", "--message", "Release")
        self.verify()

    def test_tag_may_precede_default_branch_tip(self) -> None:
        git(self.root, "tag", "v0.0.5")
        git(self.root, "commit", "--allow-empty", "-m", "Next version")
        git(self.root, "update-ref", "refs/remotes/origin/main", "HEAD")
        git(self.root, "checkout", "--detach", self.sha)
        self.verify()

    def test_uses_default_branch_from_event(self) -> None:
        git(self.root, "tag", "v0.0.5")
        git(self.root, "update-ref", "refs/remotes/origin/releases/stable", self.sha)
        git(self.root, "update-ref", "-d", "refs/remotes/origin/main")
        self.verify(event(branch="releases/stable"))

    def test_wrong_version(self) -> None:
        with self.assertRaisesRegex(ValueError, "package version tag"):
            self.verify(event(tag="v0.0.6"))

    def test_wrong_ref(self) -> None:
        with self.assertRaisesRegex(ValueError, "does not identify tag"):
            verify_release(self.root, event(), "release", self.sha, "refs/heads/main")

    def test_wrong_checkout_sha(self) -> None:
        with self.assertRaisesRegex(ValueError, "checked-out commit differs"):
            self.verify(sha="a" * 40)

    def test_invalid_sha(self) -> None:
        for value in ("HEAD", self.sha[:7], self.sha.upper()):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, "full lowercase"):
                self.verify(sha=value)

    def test_moved_tag(self) -> None:
        git(self.root, "tag", "v0.0.5")
        git(self.root, "commit", "--allow-empty", "-m", "Different commit")
        with self.assertRaisesRegex(ValueError, "release tag differs"):
            self.verify(sha=git(self.root, "rev-parse", "HEAD"))

    def test_commit_outside_default_branch(self) -> None:
        git(self.root, "commit", "--allow-empty", "-m", "Unmerged commit")
        git(self.root, "tag", "v0.0.5")
        with self.assertRaisesRegex(ValueError, "fetched default branch"):
            self.verify(sha=git(self.root, "rev-parse", "HEAD"))

    def test_missing_tag(self) -> None:
        with self.assertRaisesRegex(ValueError, "refs/tags/v0.0.5"):
            self.verify()

    def test_missing_remote_default_branch(self) -> None:
        git(self.root, "tag", "v0.0.5")
        git(self.root, "update-ref", "-d", "refs/remotes/origin/main")
        with self.assertRaisesRegex(ValueError, "refs/remotes/origin/main"):
            self.verify()

    def test_invalid_default_branch(self) -> None:
        git(self.root, "tag", "v0.0.5")
        for branch in ("../main", "main~1", "main; touch marker"):
            with (
                self.subTest(branch=branch),
                self.assertRaisesRegex(ValueError, "check-ref-format"),
            ):
                self.verify(event(branch=branch))
        self.assertFalse((self.root / "marker").exists())

    def test_release_event_requirements(self) -> None:
        payloads: list[object] = [
            [],
            {},
            {"action": "created"},
            {"action": "published"},
            {"action": "published", "release": {}},
            {"action": "published", "release": {"draft": True, "tag_name": "v0.0.5"}},
            {"action": "published", "release": {"draft": False}},
            {"action": "published", "release": {"draft": False, "tag_name": 5}},
        ]
        for payload in payloads:
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                self.verify(payload)

    def test_only_release_events_can_publish(self) -> None:
        for name in ("pull_request", "push", "workflow_dispatch"):
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, "release event"):
                verify_release(self.root, event(), name, self.sha, "refs/tags/v0.0.5")

    def test_repository_metadata_required(self) -> None:
        git(self.root, "tag", "v0.0.5")
        for repository in (None, {}, {"default_branch": 5}, {"default_branch": ""}):
            payload = event()
            payload["repository"] = repository
            with (
                self.subTest(repository=repository),
                self.assertRaisesRegex(ValueError, "repository"),
            ):
                self.verify(payload)

    def test_missing_git_identifies_failure(self) -> None:
        with patch("scripts.verify_release.subprocess.run", side_effect=FileNotFoundError("git")):
            with self.assertRaisesRegex(ValueError, "Cannot verify release with git"):
                self.verify()

    def test_missing_project_metadata(self) -> None:
        (self.root / "pyproject.toml").unlink()
        with self.assertRaises(OSError):
            self.verify()

    def test_cli_requires_github_environment(self) -> None:
        output = StringIO()
        with patch.dict(os.environ, {}, clear=True), redirect_stderr(output):
            self.assertEqual(main(), 1)
        self.assertIn("Release validation failed", output.getvalue())

    def test_cli_reports_invalid_event_json(self) -> None:
        path = self.root / "event.json"
        path.write_text("invalid JSON")
        output = StringIO()
        with patch.dict(os.environ, {"GITHUB_EVENT_PATH": str(path)}), redirect_stderr(output):
            self.assertEqual(main(), 1)
        self.assertIn("Release validation failed", output.getvalue())

    def test_json_release_payload(self) -> None:
        git(self.root, "tag", "v0.0.5")
        self.verify(json.loads(json.dumps(event())))

    def test_git_checks_ignore_inherited_git_context(self) -> None:
        git(self.root, "tag", "v0.0.5")
        with TemporaryDirectory() as directory:
            inherited = {
                "GIT_DIR": directory,
                "GIT_WORK_TREE": directory,
                "GIT_INDEX_FILE": str(Path(directory) / "index"),
                "GIT_COMMON_DIR": directory,
            }
            with patch.dict(os.environ, inherited):
                self.verify()

    def test_fixtures_run_safely_inside_git_hooks(self) -> None:
        source = Path(__file__).resolve().parent.parent
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "pytest",
                "-q",
                "test/test_release.py::TestRelease::test_lightweight_tag",
            ],
            cwd=source,
            capture_output=True,
            text=True,
            check=False,
            env={
                **os.environ,
                "GIT_DIR": str(self.root / ".git"),
                "GIT_WORK_TREE": str(self.root),
                "GIT_INDEX_FILE": str(self.root / ".git/index"),
                "GIT_COMMON_DIR": str(self.root / ".git"),
            },
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(git(self.root, "rev-parse", "HEAD"), self.sha)
        self.assertEqual(git(self.root, "tag", "--list"), "")
