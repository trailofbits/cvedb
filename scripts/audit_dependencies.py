"""Audit every locked runtime and development dependency for the active Python version."""

from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory


def _run(arguments: list[str], *, root: Path, operation: str) -> None:
    try:
        subprocess.run(arguments, cwd=root, check=True)
    except (OSError, subprocess.CalledProcessError) as error:
        raise RuntimeError(
            f"Dependency {operation} failed: {error}. Review the preceding tool output."
        ) from error


def audit(root: Path) -> None:
    """Check the lockfile and audit a temporary hashed export without resolving changes.

    Args:
        root: Project directory containing pyproject.toml and uv.lock.

    Raises:
        RuntimeError: Lock validation, export, or vulnerability auditing fails.
    """
    _run(["uv", "lock", "--check"], root=root, operation="lock validation")
    with TemporaryDirectory(prefix="cvedb-audit-") as directory:
        requirements = str(Path(directory) / "requirements.txt")
        _run(
            [
                "uv",
                "export",
                "--quiet",
                "--frozen",
                "--all-groups",
                "--no-emit-project",
                "--format",
                "requirements.txt",
                "--output-file",
                requirements,
            ],
            root=root,
            operation="export",
        )
        _run(
            [
                sys.executable,
                "-m",
                "pip_audit",
                "--strict",
                "--require-hashes",
                "--disable-pip",
                "--progress-spinner",
                "off",
                "--cache-dir",
                str(Path(directory) / "cache"),
                "-r",
                requirements,
            ],
            root=root,
            operation="vulnerability audit",
        )


def main() -> int:
    """Audit the repository's locked dependencies and report actionable failures."""
    try:
        audit(Path(__file__).resolve().parent.parent)
    except RuntimeError as error:
        print(error, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
