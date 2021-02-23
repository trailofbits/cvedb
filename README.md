# CVEdb

[![PyPI version](https://badge.fury.io/py/cvedb.svg)](https://badge.fury.io/py/cvedb)
[![Tests](https://github.com/trailofbits/cvedb/workflows/tests/badge.svg)](https://github.com/trailofbits/cvedb/actions)
[![Slack Status](https://empireslacking.herokuapp.com/badge.svg)](https://empireslacking.herokuapp.com)

CVEdb is yet another Python CVE database library and utility. There are lots already available. Why create another?
Most existing libraries rely on a third party API like [cve.circl.lu](https://cve.circl.lu/), which can and do
throttle usage, require registration, and/or demand an internet connection. Some libraries are bloated, including web
interfaces for search.

CVEdb Features:
* Can be used either as a library or a command line utility
* Simple API
* Download directly from the [National Vulnerability Database](https://nvd.nist.gov/vuln/data-feeds)
* Automatically, incrementally update as necessary

CVEdb Anti-Features:
* Does not require many dependencies
* Does not have a web server
* Does not require Internet connectivity (after the first sync)

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
    for cve in db:
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

## License and Acknowledgements

CVEdb was created by [Trail of Bits](https://www.trailofbits.com/).
It is licensed under the [GNU Lesser General Public License v3.0](LICENSE).
[Contact us](mailto:opensource@trailofbits.com) if you're looking for an exception to the terms.
© 2021, Trail of Bits.
