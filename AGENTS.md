# Repository Guidelines

## Project structure and module organization

CVEdb provides a Python library and CLI for querying a local SQLite CVE database.

- `cvedb/`: implementation. `cpe.py` and `cve.py` define vulnerability models;
  `feed.py` and `nvd.py` load feeds; `db.py`, `schemas.py`, and `sql.py` handle
  persistence; `search.py` implements queries; `cli.py` and `printing.py` handle CLI output.
- `cvedb/data/`: bundled NVD `.json.gz` feeds and matching `.meta` files for offline use.
- `test/`: tests for CPE parsing, serialization, and custom feeds.
- `setup.py`: package metadata, dependencies, development extras, and the `cvedb` entry point.
- `.github/workflows/tests.yml`: CI checks on Python 3.10–3.14. Python 3.10 is the minimum.

## Build, test, and development commands

Use an isolated environment from the repository root:

```sh
uv venv --python 3.13
source .venv/bin/activate
uv pip install -e '.[dev]'
pytest -q
pytest -q test/test_cpe.py
python -m cvedb --help
flake8 cvedb test --count --select=E9,F63,F7,F82 --show-source --statistics
```

The editable install includes development dependencies. The test commands run the full suite
or focused CPE tests; the final command reproduces CI's blocking lint check. Packaging uses
setuptools through `setup.py`; there is no separate build script.

## Coding style and naming conventions

Use four-space indentation, `snake_case` functions and variables, `PascalCase` classes, and
`UPPER_SNAKE_CASE` constants. Add type annotations to new APIs and use absolute imports.
Keep new lines within 100 characters. CI also runs advisory flake8 checks with a 127-character
limit and complexity limit of 10. No formatter or type checker is configured in the repository.

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
