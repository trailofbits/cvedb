# CVEdb

[![PyPI version](https://badge.fury.io/py/cvedb.svg)](https://badge.fury.io/py/cvedb)
[![Tests](https://github.com/trailofbits/cvedb/workflows/tests/badge.svg)](https://github.com/trailofbits/cvedb/actions)
[![Slack Status](https://slack.empirehacking.nyc/badge.svg)](https://slack.empirehacking.nyc)

CVEdb is yet another Python CVE database library and utility. There are lots already available. Why create another?
Most existing libraries rely on a third party API like [cve.circl.lu](https://cve.circl.lu/), which can and do
throttle usage, require registration, and/or demand an internet connection. Some libraries are bloated, including web
interfaces for search.

CVEdb Features:
* Can be used either as a library or a command line utility
* Simple API
* Download directly from the [National Vulnerability Database](https://nvd.nist.gov/vuln/data-feeds)
* Automatically, incrementally update at any time

CVEdb Anti-Features:
* Does not require many dependencies
* Does not have a web server
* Does not require Internet connectivity other than to download new CVEs

## Installation

```console
$ pip3 install cvedb
```

## Command Line Usage

```console
$ cvedb --help
```

## Python Examples

```python
from cvedb.db import CVEdb

with CVEdb.open() as db:
    for cve in db.data():
        print(cve)
```

By default, the CVEs downloaded from NIST are saved to a sqlite database stored in `cvedb.db.DEFAULT_DB_PATH`, which is
set to `~/.config/cvedb/cvedb.sqlite`. This can be customized by passing the `db_path` argument to `CVEdb.open`.

The `db.data()` function returns an instance of a `cvedb.feed.Data` object, which has
[numerous methods to query CVEs](https://github.com/trailofbits/cvedb/blob/master/cvedb/feed.py).
For example:
```python
with CVEdb.open() as db:
    for cve in db.data().search("search term"):
        print(cve)
```
In addition to accepting strings, the `data().search(...)` function will accept any
[`cvedb.search.SearchQuery` object](https://github.com/trailofbits/cvedb/blob/master/cvedb/search.py).

## Known Issues

The NIST National Vulnerability Database is in the process of transitioning to a new REST API. The datasets on which
CVEdb is built are still available, but it is unclear whether they may become deprecated. Also, NIST has started rate
limiting downloads, which may affect CVEdb syncing. Therefore, CVEdb ships
[pre-seeded with a database](https://github.com/trailofbits/cvedb/tree/master/cvedb/data). Therefore, CVEdb does not
require any Internet connectivity after it is installed, other than to download new CVE definitions. Also, the behavior
of CVEdb was changed from automatically checking for updates as necessary to now requiring the user explicitly request
an update with the new `--update` argument. Support for the new REST API is being tracked in
[this GitHub issue](https://github.com/trailofbits/cvedb/issues/3).

## License and Acknowledgements

CVEdb was created by [Trail of Bits](https://www.trailofbits.com/).
It is licensed under the [GNU Lesser General Public License v3.0](LICENSE).
[Contact us](mailto:opensource@trailofbits.com) if you're looking for an exception to the terms.
© 2021, Trail of Bits.

The [CVE database shipped with CVEdb](https://github.com/trailofbits/cvedb/tree/master/cvedb/data) is created and
maintained by NIST and is released in the public domain.

## CPE matching

`source.match(target)` compares a CPE criterion with a target CPE. String comparisons
are case-insensitive. Unescaped `*` matches zero or more characters, and unescaped
`?` matches zero or one character, at the beginning or end of a source attribute.
Escape literal wildcard characters with a backslash. Unescaped wildcards in target
strings have an undefined comparison in the [CPE name matching specification][cpe-name-matching].
and raise `cvedb.cpe.TestError`.

Use `Logical.ANY` for an unconstrained component. A source `Logical.ANY` matches
any target value, and a target `Logical.ANY` leaves a concrete source component
unconstrained during candidate searches. `Logical.NA` is distinct from a literal
hyphen and matches only another `Logical.NA` when used in a source criterion.

`VersionRange` checks both boundaries independently. It compares dot-separated
numeric releases numerically, treating omitted trailing zero components as equal:
`2.0 < 10.0`, and `1 == 1.0.0`. Supported prerelease suffixes sort before the final
release in this order: `dev`, `alpha`/`a`, `beta`/`b`, and `pre`/`preview`/`rc`.
An optional suffix number compares numerically. Hyphens, underscores, or periods
can separate the suffix and number. CPE escapes are decoded before comparison.
This is CVEdb's documented ordering policy, not a universal vendor version format.
An exact version equality is accepted; otherwise unsupported vendor formats raise
`TestError` instead of guessing. An unbounded range does not require ordering.
A target version of `Logical.ANY` leaves version unconstrained; `Logical.NA` does
not satisfy a bounded range.

`parse_formatted_string()` requires exactly one complete CPE 2.3 formatted string.
It rejects trailing fields, whitespace, and other suffixes. Expression
serialization handles its record-ending newline separately.

The focused CPE checks use an isolated Python environment with the development
extras installed. Run them before committing CPE changes:

```sh
uv venv --python 3.13
uv pip install -e '.[dev]'
.venv/bin/python -m pytest -q test/test_cpe_matching.py
prek run --files cvedb/cpe.py test/test_cpe_matching.py
```

## Applicability searches

A product search identifies candidate CVEs associated with a vulnerable-marked
CPE criterion. It preserves version ranges but does not prove that required
platforms are installed. Candidate associations include marked criteria inside
negated expressions; use inventory evaluation to determine the expression's
Boolean result. This distinction follows the NVD's
[CPE-based search and applicability model](https://nvd.nist.gov/developers/vulnerabilities).

```python
from cvedb.cpe import CPE
from cvedb.search import CPEQuery, EnvironmentQuery
from cvedb.db import CVEdb

application = CPE(vendor="example", product="widget", version="3.0")
platform = CPE(vendor="example", product="platform", version="1.0")

with CVEdb.open() as db:
    candidates = list(db.data().search(CPEQuery(application)))
    applicable = list(db.data().search(EnvironmentQuery([application, platform])))
```

Supply the complete inventory and concrete installed CPE names for confirmed
evaluation. Each positive criterion requires a matching inventory product; AND,
OR, and explicit negation retain their Boolean meanings. Missing products make
positive criteria false, so negation can match an empty inventory. Logical ANY
components remain unconstrained filters under the CPE matching rules.

For a CVE's `configurations`, `match(cpe)` evaluates a singleton inventory,
`match_inventory(inventory)` evaluates a complete inventory, and
`match_candidate(cpe)` finds a vulnerable-marked product association.
`CPEMatch(criterion, vulnerable=False)` marks a required environmental product;
it does not negate that criterion. Absent applicability data matches no products.
The marking and expression structure survive serialization and database storage.

Legacy empty-string and null version bounds mean an absent bound. They do not
replace an exact CPE version with a wildcard. Conflicting meaningful bounds and
non-string bound values raise an error.

## Database format

Schema version 2 keeps CVEs, descriptions, references, and CPE associations scoped
to their source feed. It preserves assigners, all CPE components, and the order of
metadata collections. Reingesting a record replaces its previous child data
atomically; callers using `Schema.add()` own the surrounding commit or rollback.
Naive timestamps mean UTC, and timezone offsets and fractional seconds preserve
the same instant through storage.

Older databases cannot reliably recover feed ownership or vulnerability marking
from their stored metadata. Opening an old schema raises an error and preserves
the original file. Create a replacement at a separate path with
`CVEdb.open("replacement.sqlite")` or `--database replacement.sqlite`. Reimport
custom feeds into the replacement. Retain the original file until you have
verified the replacement; CVEdb does not automatically delete or migrate it.

[cpe-name-matching]: https://nvlpubs.nist.gov/nistpubs/legacy/ir/nistir7696.pdf
