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

CVEdb requires Python 3.11 or later. CI tests Python 3.11–3.15.

```console
$ pip3 install cvedb
```

## Development

Install [uv](https://docs.astral.sh/uv/getting-started/installation/) 0.13.7, then
create an isolated environment from the committed lockfile:

```sh
uv lock --check
uv sync --frozen --python 3.13
uv run --frozen prek install
uv run --frozen prek auto-update --cooldown-days 7
uv run --frozen pytest -q
uv run --frozen ty check --error-on-warning cvedb test scripts
uv run --frozen prek run --all-files
uv run --frozen python -m scripts.check_dist
```

The development group pins Ruff, ty, test tools, and the cross-platform wrappers
for ShellCheck, shfmt, and actionlint. Prek runs Python lint/format and strict ty
checks across all source, tests, and distribution scripts, plus offline tests, shell
checks, and workflow checks. Python warnings fail tests. CI applies the same checks
to PRs targeting any branch, including stacked PRs. The installed package includes
a `py.typed` marker so downstream type checkers can use its annotations.

`pyproject.toml` declares the package and its exact direct dependencies. The uv build
backend keeps the existing package layout. `uv build` builds an sdist and then a wheel
from that sdist. The distribution check validates metadata, entry points, license files,
and bundled snapshots, then installs the wheel outside the source tree with hashed
runtime dependencies and exercises offline loading and querying.

When updating dependencies, check current stable releases, respect the configured
seven-day maturity policy, update the exact pins, and regenerate `uv.lock` with
`uv lock`. The uv, uv_build, Ruff, ty, and prek versions selected for this migration
are the newest stable releases eligible under that policy on November 16, 2026.

## Command Line Usage

```console
$ cvedb --help
```

Descriptions use English when available, then the first available language, or
`No description available` when none are present. CVE text escapes terminal control
characters, including embedded newlines and tabs, as visible sequences such as `\n`
and `\x1b`. Plain output keeps one tab-separated record per line. Styled output
wraps long text to the terminal width, with a minimum box width of four columns.

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

## Feed sources

CVEdb downloads NVD 2.0 yearly feeds and reads the installed legacy snapshots for
offline use. Ordinary queries use installed or previously persisted data. Years
without an installed snapshot remain empty until you explicitly request an update.
Installed snapshots have limited coverage and do not represent current NVD data.
A paginated REST API client remains tracked in [issue #3](https://github.com/trailofbits/cvedb/issues/3).

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

Run the focused CPE checks before committing CPE changes:

```sh
uv sync --frozen --python 3.13
uv run --frozen pytest -q test/test_cpe_matching.py
uv run --frozen prek run --files cvedb/cpe.py test/test_cpe_matching.py
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


## Search semantics

Text searches match literal substrings in CVE IDs, all description languages,
reference names and URLs, and assigners. Matching ignores case with Unicode
casefold unless you pass `case_sensitive=True`. Percent signs and underscores are
literal characters. `DescriptionQuery` searches descriptions only.

Date filters compare inclusive UTC instants. Naive datetimes and CLI timestamps
mean UTC. Date-only `--before` and `--modified-before` values include the entire
parsed UTC day; after filters start at midnight. Explicit timestamps, including
midnight, retain their exact instant. A year-only or month-only input denotes
its first day, rather than its entire year or month. For example, `--before 2020`
includes January 1, 2020, through 23:59:59.999999 UTC.

Description sorting uses English when present, otherwise the first description,
otherwise an empty string. An empty English description remains empty. Unknown
impact scores sort before known scores in ascending order and after them in
descending order. CVE IDs break ties for requested sort keys. Timestamp sort keys
use UTC in memory and in SQLite.

CPE and environment searches use conservative SQL candidate selection and then
evaluate complete persisted configurations. They may scan many records. Custom
query classes use in-memory filtering and ordering; matching and database errors
propagate instead of silently changing the query.

## Updates and database contexts

Use `db.reload()` to explicitly check upstream feeds. By default, checks are
limited to once per day after a successful upstream response. Use
`db.reload(force=True)` or `data(force_reload=True)` to bypass that interval.
Forcing a check still honors an upstream response confirming that data has not
changed. The CLI's `--update` option requests a forced check.

```python
from cvedb.db import CVEdb

with CVEdb.open() as db:
    updated = db.reload(force=True)
    for cve in updated:
        print(cve)
```

The returned data source reads persisted records without downloading or
initializing feeds. It uses the open database connection and records the newest
known feed timestamp when created; the timestamp is `None` when unknown. Use the
source within the connection's lifetime. A `db.data()` view refreshes its own
timestamp after initialization or its own `reload()` call.

`last_checked()` records successful explicit upstream checks. Local snapshot
initialization leaves it unset. A new source's records are ingested even when
its timestamp matches the previous source. Only returning the existing-data
object confirms unchanged data. A failed refresh rolls back the records and
metadata changed by that call. Failed due checks remain retryable, and forced
checks can always be retried immediately. Errors propagate to the caller.

The context returned by `CVEdb.open()` owns one connection and transaction.
Nested entries reuse that database and connection. Any exception leaving a nested
entry makes the entire outer transaction roll back, even if you catch the inner
exception. All writes in that outer transaction are then discarded. The outermost
exit commits or rolls back, closes the connection, and releases its state. You
can reuse the context afterward; each outer entry opens a new connection.

When you construct `CVEdb` with your own SQLite connection, you retain ownership
of that connection and any surrounding transaction. Refresh savepoints preserve
that transaction instead of committing it. Pass `parents=[]` for an empty feed
collection: counting, iteration, searching, and explicit refresh return empty
results without downloading data.


## Offline snapshots and validation

Ordinary queries of built-in NVD feeds use stored data and installed bundles.
Missing bundle pairs leave that feed unavailable offline without blocking other
installed feeds. A corrupt pair raises an error identifying its file and does
not trigger a network fallback. Custom feeds control their own initial loading.

The installed NVD snapshot contains feed years **2002–2021**, with metadata last
modified on **May 10, 2021**. The 2002 feed also contains earlier CVEs. The 2021
feed is a partial-year snapshot; registered newer feed years do not imply bundled
or current coverage. Use `--update` to request current NVD 2.0 yearly feeds.

Use `--data-version` to inspect selected feeds without loading them or contacting
the network. It shows installed complete bundle pairs and their metadata dates
separately from stored CVE counts, stored modification dates, and successful
upstream check dates. Installed metadata summarizes coverage; the report does
not decompress and hash-verify every bundle.

Both bundled and downloaded snapshots validate gzip length, uncompressed length,
and the SHA-256 of uncompressed JSON before ingestion, following the
[NVD metadata contract][nvd-feed-metadata]. Invalid gzip headers/trailers, corrupt
checksums, malformed metadata/JSON/CVEs, and excessive nesting fail with source
context. Failed updates preserve previously stored records and timestamps.

The loader limits metadata to 64 KiB, gzip data to 256 MiB, expanded JSON to 2 GiB,
and object/array nesting to 256 container levels. Network operations use a
30-second socket timeout and a 300-second transfer-loop deadline checked between
available chunks. DNS resolution follows the system resolver's timing.

[nvd-feed-metadata]: https://nvd.nist.gov/vuln/data-feeds


## CLI operations

`cvedb --update` updates the selected database and exits. Sort, descending-order,
and ANSI options alone do not request a listing after an update. Add search
terms, a date filter, or a CPE filter to update and then query. An explicitly
provided wildcard CPE value also requests a query:

```console
$ cvedb --update --vendor '*'
$ cvedb alpha beta --vendor acme --sort modified --descending
$ cvedb --update --data-version
```

Multiple search terms form an OR group; date and CPE filters combine with that
group using AND. Listings apply sorting, descending order, and ANSI options even
when you provide no search filters. The supported sort choices are `cve`,
`modified`, `published`, `impact`, and `severity`. Database paths and CPE filter
options require a value when present.

Operations run in this order: update, version output, data-version output, and
listing. Version output takes precedence over data-version output and listing;
data-version output takes precedence over listing. A successful update commits
before output starts, so an interrupted listing does not undo it.

Successful commands return status 0. Expected operation failures, interrupted
output, and cancellation return status 1; invalid arguments return status 2.
