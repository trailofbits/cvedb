"""Public feed refresh and offline initialization behavior."""

from collections.abc import Iterator
from contextlib import closing
from dataclasses import replace
from datetime import datetime, timedelta, UTC
from gzip import compress
from hashlib import sha256
from io import BytesIO
import json
from pathlib import Path
from typing import cast
import sqlite3
from unittest.mock import patch

import pytest

from cvedb.cve import CVE, Description, Reference
from cvedb.db import CVEdb, CVEdbDataSource, UPDATE_INTERVAL_SECONDS
from cvedb.feed import Data, DataSource, Feed, InMemoryData
from cvedb.nvd import JsonFeed

NOW = datetime(2020, 1, 2, tzinfo=UTC)
LATER = NOW + timedelta(days=1)


def _record(text: str = "old", number: int = 1) -> CVE:
    return CVE(f"CVE-2020-{number:04}", NOW, NOW, descriptions=(Description("en", text),))


class _OrderedSource(DataSource):
    def __init__(self, records: tuple[CVE, ...], fail: bool = False) -> None:
        super().__init__(LATER)
        self.records = records
        self.fail = fail

    def __iter__(  # ty: ignore[missing-override-decorator]  # Python 3.11 lacks override.
        self,
    ) -> Iterator[CVE]:
        for index, record in enumerate(self.records):
            if self.fail and index == 1:
                raise ValueError("second record parse failed")
            yield record


class _MutableFeed(Feed):
    register = False

    def __init__(self, name: str = "mutable", initial: Data | None = None) -> None:
        super().__init__(name, initial)
        self.source: DataSource = initial if initial is not None else InMemoryData(NOW, ())
        self.calls = 0
        self.seen: list[Data | None] = []
        self.error: Exception | None = None
        self.unchanged = False

    def reload(  # ty: ignore[missing-override-decorator]  # Python 3.11 lacks override.
        self, existing_data: Data | None = None
    ) -> DataSource:
        self.calls += 1
        self.seen.append(existing_data)
        if self.error is not None:
            raise self.error
        if existing_data is not None:
            list(existing_data)
            len(existing_data)
        if self.unchanged:
            assert existing_data is not None
            return existing_data
        return self.source


class _JsonFeed(JsonFeed):
    register = False


def _feed(name: str = "mutable") -> _MutableFeed:
    return _MutableFeed(name, InMemoryData(NOW, (_record(),)))


def _snapshot(connection: sqlite3.Connection) -> tuple[list[tuple[object, ...]], ...]:
    rows = tuple(
        connection.execute(f"SELECT * FROM {table} ORDER BY rowid").fetchall()
        for table in ("feeds", "cves", "descriptions", "refs", "cpes", "configurations")
    )
    return cast(tuple[list[tuple[object, ...]], ...], rows)


def test_public_forced_reload_reaches_upstream_and_returns_persisted_data() -> None:
    parent = _feed()
    parent.source = InMemoryData(LATER, (_record("new"),))
    with closing(sqlite3.connect(":memory:")) as connection:
        db = CVEdb(connection, [parent])
        source = db.reload(force=True)
        assert parent.calls == 1
        assert parent.seen == [None]
        assert list(source) == [_record("new")]
        assert source.last_modified_date == LATER
        assert list(db.data()) == [_record("new")]


@pytest.mark.parametrize("operation", ["iteration", "count", "search"])
def test_view_initialization_and_reload_refresh_its_timestamp(operation: str) -> None:
    parent = _feed()
    with closing(sqlite3.connect(":memory:")) as connection:
        db = CVEdb(connection, [parent])
        view = db.data()
        assert view.last_modified_date is None
        if operation == "iteration":
            assert list(view) == [_record()]
        elif operation == "count":
            assert len(view) == 1
        else:
            assert list(view.search("old")) == [_record()]
        assert view.last_modified_date == NOW
        assert parent.calls == 0
        assert db.feeds[0].last_checked() is None
        parent.source = InMemoryData(LATER, (_record("changed"),))
        updated = view.reload(force=True)
        assert list(updated) == [_record("changed")]
        assert view.last_modified_date == LATER


def test_update_throttling_is_pure_and_force_bypasses_it() -> None:
    parent = _feed()
    with closing(sqlite3.connect(":memory:")) as connection:
        db = CVEdb(connection, [parent])
        with patch("cvedb.db.time", return_value=100000.0):
            db.reload(force=True)
        before = _snapshot(connection)
        with patch("cvedb.db.time", return_value=100001.0):
            assert not db.feeds[0].is_out_of_date()
            db.reload()
        assert _snapshot(connection) == before
        assert parent.calls == 1
        with patch("cvedb.db.time", return_value=100000.0 + UPDATE_INTERVAL_SECONDS):
            assert db.feeds[0].is_out_of_date()
            assert _snapshot(connection) == before
            db.reload()
        assert parent.calls == 2
        with patch("cvedb.db.time", return_value=100002.0):
            db.reload(force=True)
        assert parent.calls == 3


def test_confirmed_unchanged_response_advances_only_checked_time() -> None:
    parent = _feed()
    with closing(sqlite3.connect(":memory:")) as connection:
        db = CVEdb(connection, [parent])
        assert list(db.data()) == [_record()]
        parent.unchanged = True
        with patch("cvedb.db.time", return_value=100000.5):
            source = db.reload(force=True)
        assert list(source) == [_record()]
        assert source.last_modified_date == NOW
        assert db.feeds[0].last_checked() == datetime.fromtimestamp(100000.5, UTC)
        assert len(parent.seen) == 1
        assert isinstance(parent.seen[0], Data)
        assert not isinstance(parent.seen[0], type(db.data()))


def test_new_source_with_same_timestamp_still_persists_corrections() -> None:
    parent = _feed()
    with closing(sqlite3.connect(":memory:")) as connection:
        db = CVEdb(connection, [parent])
        assert list(db.data()) == [_record()]
        parent.source = InMemoryData(NOW, (_record("corrected"),))
        assert list(db.reload(force=True)) == [_record("corrected")]


@pytest.mark.parametrize("failure", ["network", "parsing", "persistence", "timestamp"])
def test_failed_updates_preserve_feed_and_remain_retryable(failure: str) -> None:
    parent = _feed()
    with closing(sqlite3.connect(":memory:")) as connection:
        db = CVEdb(connection, [parent])
        assert list(db.data()) == [_record()]
        changed = _record("changed")
        second = replace(_record("second", 2), references=(Reference(url="reject"),))
        parent.source = _OrderedSource((changed, second), fail=failure == "parsing")
        if failure == "network":
            parent.error = OSError("offline")
        if failure == "timestamp":
            parent.source = InMemoryData(None, (changed,))
        if failure == "persistence":
            connection.execute(
                "CREATE TRIGGER reject_ref BEFORE INSERT ON refs WHEN NEW.url='reject' "
                "BEGIN SELECT RAISE(FAIL, 'reference rejected'); END"
            )
        before = _snapshot(connection)
        with pytest.raises((OSError, ValueError, sqlite3.IntegrityError)):
            db.reload()
        assert _snapshot(connection) == before
        assert db.feeds[0].is_out_of_date()
        parent.error = None
        parent.source = InMemoryData(LATER, (changed,))
        assert list(db.reload()) == [changed]
        assert parent.calls == 2


def test_failed_recent_forced_update_can_be_forced_again_immediately() -> None:
    parent = _feed()
    with closing(sqlite3.connect(":memory:")) as connection:
        db = CVEdb(connection, [parent])
        with patch("cvedb.db.time", return_value=100000.0):
            db.reload(force=True)
        before = _snapshot(connection)
        parent.error = OSError("offline")
        with pytest.raises(OSError), patch("cvedb.db.time", return_value=100001.0):
            db.reload(force=True)
        assert _snapshot(connection) == before
        parent.error = None
        parent.source = InMemoryData(LATER, (_record("retry"),))
        with patch("cvedb.db.time", return_value=100002.0):
            assert list(db.reload(force=True)) == [_record("retry")]
        assert parent.calls == 3


def test_later_feed_failure_rolls_back_earlier_feed_even_if_caught() -> None:
    first, second = _feed("first"), _feed("second")
    with closing(sqlite3.connect(":memory:")) as connection:
        db = CVEdb(connection, [first, second])
        list(db.data())
        first.source = InMemoryData(LATER, (_record("changed"),))
        second.error = OSError("second feed offline")
        before = _snapshot(connection)
        with pytest.raises(OSError, match="second feed offline"):
            db.reload(force=True)
        assert _snapshot(connection) == before
        assert list(db.data()) == [_record(), _record()]


@pytest.mark.parametrize("source", ["database", "feed"])
def test_force_reload_data_argument_requests_real_update(source: str) -> None:
    parent = _feed()
    parent.source = InMemoryData(LATER, (_record("forced"),))
    with closing(sqlite3.connect(":memory:")) as connection:
        db = CVEdb(connection, [parent])
        target = db if source == "database" else db.feeds[0]
        assert list(target.data(force_reload=True)) == [_record("forced")]
        assert parent.calls == 1


def _payload(text: str) -> tuple[bytes, bytes]:
    raw = json.dumps(
        {
            "CVE_data_timestamp": NOW.isoformat(),
            "CVE_Items": [
                {
                    "cve": {
                        "CVE_data_meta": {"ID": "CVE-2020-0001"},
                        "description": {"description_data": [{"lang": "en", "value": text}]},
                    },
                    "publishedDate": NOW.isoformat(),
                    "lastModifiedDate": NOW.isoformat(),
                    "impact": {},
                }
            ],
        }
    ).encode()
    compressed = compress(raw, mtime=0)
    meta = (
        f"lastModifiedDate:{NOW.isoformat()}\nsize:{len(raw)}\nzipSize:0\n"
        f"gzSize:{len(compressed)}\nsha256:{sha256(raw).hexdigest()}\n"
    ).encode()
    return compressed, meta


def test_fresh_forced_json_update_bypasses_existing_bundle(tmp_path: Path) -> None:
    parent = _JsonFeed("fixture")
    parent.cached_json_path = tmp_path / "bundle.json.gz"
    parent.cached_meta_path = tmp_path / "bundle.meta"
    old, old_meta = _payload("old")
    parent.cached_json_path.write_bytes(old)
    parent.cached_meta_path.write_bytes(old_meta)
    new, new_meta = _payload("network")
    with (
        closing(sqlite3.connect(":memory:")) as connection,
        patch("cvedb.nvd.urllib.request.urlopen", return_value=BytesIO(new_meta)) as request,
        patch("cvedb.nvd.download", return_value=new) as download,
    ):
        db = CVEdb(connection, [parent])
        assert list(db.reload(force=True))[0].description() == "network"
        request.assert_called_once()
        download.assert_called_once()


def test_missing_json_bundle_is_cached_empty_without_network(tmp_path: Path) -> None:
    parent = _JsonFeed("missing")
    parent.cached_json_path = tmp_path / "absent.json.gz"
    parent.cached_meta_path = tmp_path / "absent.meta"
    with patch("cvedb.nvd.urllib.request.urlopen", side_effect=AssertionError("network")):
        data = parent.data()
        assert parent.data() is data
        assert len(data) == 0
        assert data.last_modified_date is None
        with closing(sqlite3.connect(":memory:")) as connection:
            db = CVEdb(connection, [parent])
            view = db.data()
            assert len(view) == 0
            assert list(view) == []
            assert list(view.search("")) == []
            assert view.last_modified_date is None
            assert db.feeds[0].last_checked() is None


def test_custom_initial_load_is_cached_and_failures_can_retry() -> None:
    parent = _MutableFeed()
    parent.source = InMemoryData(NOW, ())
    parent.error = OSError("initial failure")
    with closing(sqlite3.connect(":memory:")) as connection:
        db = CVEdb(connection, [parent])
        view = db.data()
        with pytest.raises(OSError, match="initial failure"):
            list(view)
        parent.error = None
        assert len(view) == 0
        assert list(view) == []
        assert parent.calls == 2
        assert view.last_modified_date == NOW


def test_persisted_result_does_not_initialize_and_has_empty_feed_semantics() -> None:
    with closing(sqlite3.connect(":memory:")) as connection:
        db = CVEdb(connection, [])
        source = CVEdbDataSource(db)
        assert list(source) == []
        assert source.last_modified_date is None
        assert len(db.data()) == 0
        assert list(db.data().search("")) == []
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 2


def test_fresh_aggregate_failure_does_not_skip_later_offline_initialization() -> None:
    first, second = _feed("first"), _feed("second")
    first.source = InMemoryData(LATER, (_record("discarded update"),))
    second.error = OSError("failed explicit update")
    with closing(sqlite3.connect(":memory:")) as connection:
        db = CVEdb(connection, [first, second])
        with pytest.raises(OSError, match="failed explicit update"):
            db.reload(force=True)
        assert connection.execute("SELECT COUNT(*) FROM cves").fetchone()[0] == 0
        assert list(db.data()) == [_record(), _record()]
        assert first.calls == second.calls == 1
        assert db.last_modified() == NOW
        assert all(feed.last_checked() is None for feed in db.feeds)


def test_cached_empty_initial_source_can_have_unknown_date() -> None:
    parent = _MutableFeed(initial=InMemoryData(None, ()))
    with closing(sqlite3.connect(":memory:")) as connection:
        db = CVEdb(connection, [parent])
        view = db.data()
        assert list(view) == []
        assert len(view) == 0
        assert view.last_modified_date is None
        assert parent.calls == 0


def test_unknown_initial_source_with_records_is_rejected_and_retryable() -> None:
    parent = _MutableFeed(initial=InMemoryData(None, (_record(),)))
    with closing(sqlite3.connect(":memory:")) as connection:
        db = CVEdb(connection, [parent])
        with pytest.raises(ValueError, match="Cannot initialize feed.*timestamp"):
            list(db.data())
        parent._data = InMemoryData(NOW, (_record(),))
        assert list(db.data()) == [_record()]


@pytest.mark.parametrize("operation", ["parent", "database"])
def test_none_upstream_update_is_not_treated_as_unchanged(operation: str) -> None:
    parent = _feed()
    with closing(sqlite3.connect(":memory:")) as connection:
        db = CVEdb(connection, [parent])
        with patch.object(parent, "reload", return_value=None):
            with pytest.raises(TypeError, match="upstream must return a DataSource"):
                if operation == "parent":
                    parent.data(force_reload=True)
                else:
                    db.reload(force=True)
        assert connection.execute("SELECT COUNT(*) FROM cves").fetchone()[0] == 0
        assert db.feeds[0].last_checked() is None


def test_successful_update_persists_across_owned_context_reopen(tmp_path: Path) -> None:
    parent = _feed()
    parent.source = InMemoryData(LATER, (_record("persisted"),))
    path = tmp_path / "updated.sqlite"
    with CVEdb.open(path, [parent]) as db:
        assert list(db.reload(force=True)) == [_record("persisted")]
    with CVEdb.open(path, [parent]) as reopened:
        assert list(reopened.data()) == [_record("persisted")]
        assert reopened.last_modified() == LATER
        assert reopened.feeds[0].last_checked() is not None
    assert parent.calls == 1


def test_direct_json_force_reload_does_not_reuse_cached_bundle(tmp_path: Path) -> None:
    parent = _JsonFeed("direct")
    parent.cached_json_path = tmp_path / "initial.json.gz"
    parent.cached_meta_path = tmp_path / "initial.meta"
    old, metadata = _payload("old")
    parent.cached_json_path.write_bytes(old)
    parent.cached_meta_path.write_bytes(metadata)
    assert list(parent.data())[0].description() == "old"
    parent._data = InMemoryData(NOW - timedelta(days=1), (_record(),))
    current, current_metadata = _payload("network")
    with (
        patch("cvedb.nvd.urllib.request.urlopen", return_value=BytesIO(current_metadata)),
        patch("cvedb.nvd.download", return_value=current) as download,
    ):
        assert list(parent.data(force_reload=True))[0].description() == "network"
        download.assert_called_once()


def test_json_unchanged_response_skips_download_even_when_forced(tmp_path: Path) -> None:
    parent = _JsonFeed("unchanged")
    parent.cached_json_path = tmp_path / "initial.json.gz"
    parent.cached_meta_path = tmp_path / "initial.meta"
    old, metadata = _payload("old")
    parent.cached_json_path.write_bytes(old)
    parent.cached_meta_path.write_bytes(metadata)
    with (
        closing(sqlite3.connect(":memory:")) as connection,
        patch("cvedb.nvd.urllib.request.urlopen", return_value=BytesIO(metadata)) as request,
        patch("cvedb.nvd.download", side_effect=AssertionError("unchanged download")),
    ):
        db = CVEdb(connection, [parent])
        assert list(db.data())[0].description() == "old"
        assert list(db.reload(force=True))[0].description() == "old"
        request.assert_called_once()
        assert db.feeds[0].last_checked() is not None


@pytest.mark.parametrize("operation", ["parent", "database"])
def test_default_initial_loader_rejects_none_from_custom_reload(operation: str) -> None:
    parent = _MutableFeed()
    with closing(sqlite3.connect(":memory:")) as connection:
        db = CVEdb(connection, [parent])
        with patch.object(parent, "reload", return_value=None):
            with pytest.raises(TypeError, match="Cannot initialize feed.*return a DataSource"):
                if operation == "parent":
                    parent.data()
                else:
                    list(db.data())
        assert parent._data is None
        assert connection.execute("SELECT COUNT(*) FROM cves").fetchone()[0] == 0
        assert len(parent.data() if operation == "parent" else db.data()) == 0
