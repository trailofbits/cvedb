"""Build distributions and verify a clean installation outside the source tree."""

import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys
from tempfile import TemporaryDirectory

from scripts.verify_dist import verify


def _run(*args: str, cwd: Path) -> None:
    subprocess.run(args, cwd=cwd, check=True)


def _check_install(root: Path, target: Path, wheel: Path) -> None:
    environment = target / "venv"
    _run("uv", "venv", "--python", sys.executable, str(environment), cwd=target)
    python = str(environment / "bin" / "python")
    requirements = str(target / "requirements.txt")
    _run(
        "uv",
        "export",
        "--frozen",
        "--no-dev",
        "--no-emit-project",
        "--output-file",
        requirements,
        cwd=root,
    )
    _run(
        "uv",
        "pip",
        "install",
        "--python",
        python,
        "--require-hashes",
        "--requirements",
        requirements,
        cwd=target,
    )
    _run("uv", "pip", "install", "--python", python, "--no-deps", str(wheel), cwd=target)
    _run(python, "-I", str(root / "scripts" / "smoke_installed.py"), cwd=target)
    _run(str(environment / "bin" / "cvedb"), "--help", cwd=target)
    _run(python, "-I", "-m", "cvedb", "--version", cwd=target)


def _retain(sdist: Path, wheel: Path, output: Path) -> None:
    try:
        output.mkdir(parents=True, exist_ok=False)
    except FileExistsError as error:
        raise ValueError(
            f"Artifact output already exists: {output}; choose a new directory"
        ) from error
    for artifact in (sdist, wheel):
        shutil.copy2(artifact, output / artifact.name)


def check_distributions(root: Path, output: Path | None = None) -> None:
    """Build, verify, and test installed distributions before optionally retaining them.

    Args:
        root: Source tree containing the package and lockfile.
        output: New directory receiving only the verified source and wheel archives.

    Raises:
        ValueError: Verification fails or the output directory already exists.
        OSError: Files cannot be built, read, installed, or retained.
        subprocess.CalledProcessError: A build, metadata, or installed behavior check fails.
    """
    _run("uv", "lock", "--check", cwd=root)
    with TemporaryDirectory(prefix="cvedb-dist-") as directory:
        target = Path(directory)
        subprocess.run(
            ["uv", "build", "--out-dir", str(target)],
            cwd=root,
            check=True,
            env={**os.environ, "UV_NO_CACHE": "true"},
        )
        sdist, wheel = next(target.glob("*.tar.gz")), next(target.glob("*.whl"))
        verify(sdist, wheel, root)
        _run(sys.executable, "-m", "twine", "check", "--strict", str(sdist), str(wheel), cwd=root)
        _check_install(root, target, wheel)
        if output is not None:
            _retain(sdist, wheel, output)


def main() -> None:
    """Build verified distributions, retaining them only when --out-dir is supplied."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-dir", type=Path, help="new directory receiving verified archives")
    args = parser.parse_args()
    check_distributions(Path(__file__).resolve().parent.parent, args.out_dir)


if __name__ == "__main__":
    main()
