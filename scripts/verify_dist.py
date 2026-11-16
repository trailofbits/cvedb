"""Check distribution metadata and the bundled offline snapshot against the source tree."""

import argparse
from collections.abc import Mapping
from configparser import ConfigParser
from email.parser import BytesParser
from email.policy import default
from pathlib import Path
import tarfile
import tomllib
from typing import TypedDict, cast
import zipfile

Project = TypedDict(
    "Project",
    {
        "name": str,
        "version": str,
        "requires-python": str,
        "license": str,
        "dependencies": list[str],
        "scripts": dict[str, str],
    },
)


def _required_files(root: Path) -> set[str]:
    files = {"README.md", "LICENSE", "pyproject.toml", "uv.lock", "AGENTS.md", "CODEOWNERS"}
    for directory in ("cvedb", "test", "scripts"):
        for path in (root / directory).rglob("*"):
            if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc":
                files.add(path.relative_to(root).as_posix())
    return files


def _check_files(contents: Mapping[str, bytes], required: set[str], root: Path) -> None:
    missing = required - contents.keys()
    if missing:
        raise ValueError(f"Distribution is missing required files: {sorted(missing)}")
    for name in required:
        expected = (root / name).read_bytes()
        same = contents[name] == expected
        if name == "pyproject.toml":
            same = tomllib.loads(contents[name].decode()) == tomllib.loads(expected.decode())
        if not same:
            raise ValueError(f"Distribution file differs from the source tree: {name}")
    forbidden = (".venv", ".uv-cache", ".pytest_cache", ".ruff_cache", "__pycache__", "build")
    for name in contents:
        if any(part in forbidden for part in Path(name).parts) or name.endswith((".pyc", ".pyo")):
            raise ValueError(f"Distribution contains a generated or cached file: {name}")


def _check_metadata(data: bytes, project: Project) -> None:
    metadata = BytesParser(policy=default).parsebytes(data)
    for field, key in (
        ("Name", "name"),
        ("Version", "version"),
        ("Requires-Python", "requires-python"),
    ):
        if metadata[field] != project[key]:
            raise ValueError(f"Distribution {field} differs from pyproject.toml")
    if metadata["License-Expression"] != project["license"]:
        raise ValueError("Distribution does not preserve its license expression")
    if metadata.get_all("License-File") != ["LICENSE"]:
        raise ValueError("Distribution does not declare its license file")
    actual = set(metadata.get_all("Requires-Dist", []))
    if actual != set(project["dependencies"]):
        raise ValueError("Distribution runtime dependencies differ from pyproject.toml")


def _member(contents: Mapping[str, bytes], name: str) -> bytes:
    try:
        return contents[name]
    except KeyError as error:
        raise ValueError(f"Distribution is missing required metadata file: {name}") from error


def verify(sdist: Path, wheel: Path, root: Path) -> None:
    """Verify source and wheel contents, metadata, and the console entry point.

    Args:
        sdist: Source distribution to inspect without extraction.
        wheel: Wheel built from the source distribution.
        root: Source tree containing the authoritative project and data files.

    Raises:
        ValueError: An archive omits, changes, or adds an invalid package file.
    """
    project = cast(Project, tomllib.loads((root / "pyproject.toml").read_text())["project"])
    with tarfile.open(sdist, "r:gz") as archive:
        source = {}
        for item in archive.getmembers():
            if item.isfile():
                stream = archive.extractfile(item)
                if stream is None:
                    raise ValueError(f"Cannot read source distribution member: {item.name}")
                source[item.name.split("/", 1)[1]] = stream.read()
    _check_files(source, _required_files(root), root)
    _check_metadata(_member(source, "PKG-INFO"), project)
    with zipfile.ZipFile(wheel) as archive:
        contents = {name: archive.read(name) for name in archive.namelist()}
    package = {name for name in _required_files(root) if name.startswith("cvedb/")}
    package.discard("cvedb/data/download.sh")
    _check_files(contents, package, root)
    info = f"{project['name']}-{project['version']}.dist-info/"
    _check_metadata(_member(contents, info + "METADATA"), project)
    if contents.get(info + "licenses/LICENSE") != (root / "LICENSE").read_bytes():
        raise ValueError("Wheel does not include the project license")
    entrypoints = ConfigParser()
    entrypoints.read_string(_member(contents, info + "entry_points.txt").decode())
    if (
        not entrypoints.has_section("console_scripts")
        or dict(entrypoints["console_scripts"]) != project["scripts"]
    ):
        raise ValueError("Wheel console scripts differ from pyproject.toml")
    if any(not name.startswith(("cvedb/", info)) for name in contents):
        raise ValueError("Wheel contains files outside the package and distribution metadata")


def main() -> None:
    """Check the sdist and wheel supplied on the command line."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("sdist", type=Path)
    parser.add_argument("wheel", type=Path)
    args = parser.parse_args()
    verify(args.sdist, args.wheel, Path(__file__).resolve().parent.parent)


if __name__ == "__main__":
    main()
