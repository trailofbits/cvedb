# Repository Guidelines

## Project structure and module organization

CVEdb provides a Python library and CLI for querying a local SQLite CVE database.

- `cvedb/`: implementation. `cpe.py` and `cve.py` define vulnerability models;
  `feed.py` and `nvd.py` load feeds; `db.py`, `schemas.py`, and `sql.py` handle
  persistence; `search.py` implements queries; `cli.py` and `printing.py` handle CLI output.
- `cvedb/data/`: bundled NVD `.json.gz` feeds and matching `.meta` files for offline use.
- `test/`: tests for CPE parsing, serialization, and custom feeds.
- `pyproject.toml` and `uv.lock`: package metadata, pinned dependencies, checks, and entry point.
- `scripts/`: distribution verification and installed-package offline smoke checks.
- `.github/workflows/tests.yml`: CI checks on Python 3.11–3.15. Python 3.11 is the minimum.

## Build, test, and development commands

Use an isolated environment from the repository root:

```sh
uv lock --check
uv sync --frozen --python 3.13
uv run --frozen prek install
uv run --frozen prek auto-update --cooldown-days 7
uv run --frozen pytest -q
uv run --frozen ty check --error-on-warning cvedb test scripts
uv run --frozen pytest -q test/test_cpe.py
uv run --frozen python -m cvedb --help
uv run --frozen prek run --all-files
uv run --frozen python -m scripts.check_dist
```

Use uv 0.13.7. Frozen sync installs the package and pinned development group in `.venv`.
Prek reproduces CI's blocking lint, formatting, typing, test, shell, and workflow checks.
Packaging uses the pinned uv_build backend. The distribution check builds an sdist and its wheel,
validates their metadata and contents, and checks a clean installed wheel outside the source tree.

## Coding style and naming conventions

Use four-space indentation, `snake_case` functions and variables, `PascalCase` classes, and
`UPPER_SNAKE_CASE` constants. Add type annotations to new APIs and use absolute imports.
Keep new lines within 100 characters. Ruff targets Python 3.11 and enforces formatting and a
complexity limit of 8. Ty checks all Python source, tests, and distribution scripts with Python
3.11 semantics and all rules treated as errors. The package includes a `py.typed` marker for
downstream type checking.

## Testing guidelines

Tests use `unittest.TestCase`, discovered by pytest. Name files `test/test_<module>.py` and
methods `test_<behavior>`. Add regression tests for behavior changes, including malformed
inputs, boundary conditions, and serialization round trips. Keep tests independent of live
NVD downloads; use custom feeds and temporary databases. No coverage threshold is configured.

## Commit and pull request guidelines

Recent commits use short, imperative subjects, such as `Update rstr` and
`Use importlib instead of pkg_resources`. Keep commits focused and subjects within 72 characters.
Submit changes through a feature branch and pull request. Describe the resulting behavior,
link relevant issues, and list validation commands and results. Update usage documentation
when CLI or library behavior changes.

## Data and configuration

The default database is `~/.config/cvedb/cvedb.sqlite`; use `--database PATH` for isolated local
experiments. Downloads require an explicit `--update`. Treat bundled feed updates as separate
data changes and preserve their matching metadata and NIST attribution.
