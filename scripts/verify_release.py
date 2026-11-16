"""Verify that a published release identifies the checked-out default-branch commit."""

import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tomllib
from typing import cast


def _git(root: Path, *arguments: str) -> str:
    try:
        result = subprocess.run(
            ["git", *arguments],
            cwd=root,
            check=True,
            capture_output=True,
            text=True,
            env={key: value for key, value in os.environ.items() if not key.startswith("GIT_")},
        )
    except (OSError, subprocess.CalledProcessError) as error:
        detail = error.stderr.strip() if isinstance(error, subprocess.CalledProcessError) else error
        raise ValueError(
            f"Cannot verify release with git {' '.join(arguments)}: {detail}"
        ) from error
    return result.stdout.strip()


def _release_tag(event: object, event_name: str) -> str:
    if event_name != "release" or not isinstance(event, dict):
        raise ValueError("Publishing requires a release event")
    event = cast(dict[str, object], event)
    if event.get("action") != "published":
        raise ValueError("Publishing requires the release published action")
    release = event.get("release")
    if not isinstance(release, dict):
        raise ValueError("The release event must contain a release object")
    release = cast(dict[str, object], release)
    if release.get("draft") is not False:
        raise ValueError("Publishing requires a published, non-draft release")
    tag = release.get("tag_name")
    if not isinstance(tag, str) or not tag:
        raise ValueError("The release must name a tag")
    return tag


def _default_branch(event: object) -> str:
    repository = cast(dict[str, object], event).get("repository")
    if not isinstance(repository, dict):
        raise ValueError("The release event must identify its repository")
    branch = cast(dict[str, object], repository).get("default_branch")
    if not isinstance(branch, str) or not branch:
        raise ValueError("The release event must identify its repository's default branch")
    return f"refs/remotes/origin/{branch}"


def verify_release(root: Path, event: object, event_name: str, sha: str, ref: str) -> None:
    """Require a published tag, package version, and commit on the default branch to agree.

    Args:
        root: Complete checkout including tags and the remote default-branch ref.
        event: Decoded GitHub release event payload.
        event_name: GitHub event type.
        sha: Full commit SHA supplied by the workflow event.
        ref: Full tag reference supplied by the workflow event.

    Raises:
        ValueError: The event, version, tag, checkout, or default-branch ancestry disagrees.
        OSError: Project metadata cannot be read.
    """
    tag = _release_tag(event, event_name)
    version = tomllib.loads((root / "pyproject.toml").read_text())["project"]["version"]
    if tag != f"v{version}":
        raise ValueError(f"Release tag {tag!r} must equal the package version tag 'v{version}'")
    if ref != f"refs/tags/{tag}":
        raise ValueError(f"Release event ref {ref!r} does not identify tag {tag!r}")
    if re.fullmatch("[0-9a-f]{40}", sha) is None:
        raise ValueError("The release event must identify a full lowercase GitHub commit SHA")
    if _git(root, "rev-parse", "--verify", "HEAD^{commit}") != sha:
        raise ValueError("The checked-out commit differs from the release event SHA")
    if (
        _git(root, "rev-parse", "--verify", "--end-of-options", f"refs/tags/{tag}^{{commit}}")
        != sha
    ):
        raise ValueError("The release tag differs from the release event SHA")
    branch = _default_branch(event)
    _git(root, "check-ref-format", branch)
    _git(root, "rev-parse", "--verify", "--end-of-options", f"{branch}^{{commit}}")
    try:
        _git(root, "merge-base", "--is-ancestor", sha, branch)
    except ValueError as error:
        raise ValueError(
            f"Release commit {sha} must be on the fetched default branch {branch}"
        ) from error


def main() -> int:
    """Validate the current GitHub release event and explain failed prerequisites."""
    try:
        verify_release(
            Path(__file__).resolve().parent.parent,
            json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text()),
            os.environ["GITHUB_EVENT_NAME"],
            os.environ["GITHUB_SHA"],
            os.environ["GITHUB_REF"],
        )
    except (OSError, ValueError, KeyError) as error:
        print(f"Release validation failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
