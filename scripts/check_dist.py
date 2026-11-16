"""Build distributions and verify a clean installation outside the source tree."""

import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory

from scripts.verify_dist import verify


def _run(*args: str, cwd: Path) -> None:
    subprocess.run(args, cwd=cwd, check=True)


def main() -> None:
    """Build an sdist and its wheel, then test metadata and a hashed offline install."""
    root = Path(__file__).resolve().parent.parent
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


if __name__ == "__main__":
    main()
