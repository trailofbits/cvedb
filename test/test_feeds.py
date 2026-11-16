from contextlib import closing, nullcontext
from dataclasses import replace
from datetime import timedelta
from io import StringIO
from pathlib import Path
import sqlite3
from unittest.mock import patch

import pytest

from cvedb import cli, nvd
from cvedb.db import CVEdb
from test.feed_fixtures import LocalJsonFeed, NOW, local_feed, route, snapshot


def _stored(db: CVEdb) -> list[tuple[str, list[tuple[object, ...]]]]:
    return [
        (table, db.connection.execute(f"SELECT * FROM {table} ORDER BY rowid").fetchall())
        for table in ("feeds", "cves", "descriptions", "refs", "cpes", "configurations")
    ]


@pytest.mark.parametrize("damage", ["hash", "compressed size", "expanded size"])
def test_cached_snapshot_mismatch_fails_with_path(tmp_path: Path, damage: str) -> None:
    value = snapshot()
    changes = {
        "hash": {"sha256": b"0" * 32},
        "compressed size": {"gz_size": 1},
        "expanded size": {"size": 1},
    }
    corrupted = replace(value, meta=replace(value.meta, **changes[damage]))
    feed = local_feed(tmp_path, corrupted)
    with patch("cvedb.nvd.urllib.request.urlopen", side_effect=AssertionError("network")):
        with pytest.raises(ValueError, match="fixture"):
            feed.data()


@pytest.mark.parametrize(
    "payload",
    [
        b"{",
        b"\xff",
        b"[]",
        b"null",
        b"123",
        b'{"CVE_Items":[{}]}',
        b'{"CVE_Items":null}',
        b'{"CVE_Items":"bad"}',
        b'{"vulnerabilities":"bad"}',
        b'{"CVE_Items":[],"x":NaN}',
        None,
    ],
)
def test_invalid_json_snapshots_preserve_existing_database(
    tmp_path: Path, payload: bytes | None
) -> None:
    if payload is None:
        depth = 300
        payload = b'{"unused":' + b"[" * depth + b"0" + b"]" * depth + b',"CVE_Items":[]}'
    feed = local_feed(tmp_path, snapshot("old"))
    incoming = snapshot(raw=payload)
    incoming = replace(
        incoming, meta=replace(incoming.meta, last_modified_date=NOW + timedelta(days=1))
    )
    with closing(sqlite3.connect(":memory:")) as connection:
        db = CVEdb(connection, [feed])
        assert len(list(db.data())) == 1
        before = _stored(db)
        with patch("cvedb.nvd.urllib.request.urlopen", side_effect=route(incoming)):
            with pytest.raises(ValueError, match="fixture"):
                db.reload(force=True)
        assert _stored(db) == before


@pytest.mark.parametrize("damage", ["truncated", "crc", "header"])
def test_invalid_gzip_preserves_existing_database(tmp_path: Path, damage: str) -> None:
    value = snapshot("new")
    variants = {
        "truncated": value.compressed[:-4],
        "crc": value.compressed[:-8] + bytes([value.compressed[-8] ^ 1]) + value.compressed[-7:],
        "header": b"invalid gzip",
    }
    compressed = variants[damage]
    incoming = replace(
        value,
        compressed=compressed,
        meta=replace(
            value.meta, gz_size=len(compressed), last_modified_date=NOW + timedelta(days=1)
        ),
    )
    feed = local_feed(tmp_path, snapshot("old"))
    with closing(sqlite3.connect(":memory:")) as connection:
        db = CVEdb(connection, [feed])
        list(db.data())
        before = _stored(db)
        with patch("cvedb.nvd.urllib.request.urlopen", side_effect=route(incoming)):
            with pytest.raises(ValueError, match="fixture"):
                db.reload(force=True)
        assert _stored(db) == before


@pytest.mark.parametrize("constant", ["_MAX_META_BYTES", "_MAX_GZIP_BYTES", "_MAX_JSON_BYTES"])
def test_snapshot_limits_apply_before_ingestion(tmp_path: Path, constant: str) -> None:
    feed = local_feed(tmp_path, snapshot())
    with patch.object(nvd, constant, 8, create=True):
        with pytest.raises(ValueError, match="fixture"):
            feed.data()


def test_offline_missing_pairs_do_not_block_available_feed(tmp_path: Path) -> None:
    good = local_feed(tmp_path, snapshot(), name="2021")
    missing = LocalJsonFeed("2099")
    missing.cached_json_path = tmp_path / "missing.gz"
    missing.cached_meta_path = tmp_path / "missing.meta"
    with patch("cvedb.nvd.urllib.request.urlopen", side_effect=AssertionError("network")):
        with closing(sqlite3.connect(":memory:")) as connection:
            db = CVEdb(connection, [good, missing])
            assert len(list(db.data())) == 1
            assert len(list(db.data())) == 1
            assert db.feeds[1].last_modified() is None
            assert db.feeds[1].last_checked() is None


def test_data_version_reports_bundles_without_loading_or_network(tmp_path: Path) -> None:
    feed = local_feed(tmp_path, snapshot(), name="2021")
    missing = LocalJsonFeed("2099")
    missing.cached_json_path = tmp_path / "missing.gz"
    missing.cached_meta_path = tmp_path / "missing.meta"
    output = StringIO()
    with CVEdb.open(tmp_path / "reported.sqlite", [feed, missing]) as db:
        with (
            patch("cvedb.cli.CVEdb.open", return_value=nullcontext(db)),
            patch.object(feed, "_load_initial", side_effect=AssertionError("initialization")),
            patch("cvedb.nvd.urllib.request.urlopen", side_effect=AssertionError("network")),
            patch("cvedb.cli.sys.stdout", output),
        ):
            assert cli.main(["cvedb", "--data-version"]) == 0
        assert db.connection.execute("SELECT COUNT(*) FROM cves").fetchone()[0] == 0
    assert "Installed bundles" in output.getvalue()
    assert "Bundled" in output.getvalue()
    assert "Stored" in output.getvalue()
    assert "2099" in output.getvalue()


def _invalid_metadata(value: bytes, damage: str) -> bytes:
    replacements = {
        "missing": lambda: b"lastModifiedDate:2020-01-02T00:00:00Z\n",
        "duplicate": lambda: value + b"size:1\n",
        "unknown": lambda: value + b"unknown:1\n",
        "negative": lambda: value.replace(b"zipSize:0", b"zipSize:-1"),
        "hash": lambda: value.replace(b"sha256:", b"sha256:xx"),
        "timestamp": lambda: value.replace(NOW.isoformat().encode(), b"invalid-date"),
        "utf8": lambda: b"\xff",
        "oversized": lambda: value + b" " * (64 * 1024),
    }
    return replacements[damage]()


@pytest.mark.parametrize(
    "damage",
    ["missing", "duplicate", "unknown", "negative", "hash", "timestamp", "utf8", "oversized"],
)
def test_invalid_metadata_preserves_stored_records_and_check_date(
    tmp_path: Path, damage: str
) -> None:
    from test.feed_fixtures import Response

    value = snapshot()
    feed = local_feed(tmp_path, value)
    with closing(sqlite3.connect(":memory:")) as connection:
        db = CVEdb(connection, [feed])
        list(db.data())
        before = _stored(db)
        with patch(
            "cvedb.nvd.urllib.request.urlopen",
            return_value=Response(_invalid_metadata(value.metadata(), damage)),
        ):
            with pytest.raises(ValueError, match="fixture"):
                db.reload(force=True)
        assert _stored(db) == before


@pytest.mark.parametrize("damage", ["hash", "compressed size", "expanded size"])
def test_upstream_integrity_mismatch_preserves_database(tmp_path: Path, damage: str) -> None:
    value = snapshot("new")
    changes = {
        "hash": {"sha256": b"0" * 32},
        "compressed size": {"gz_size": 1},
        "expanded size": {"size": 1},
    }
    incoming = replace(
        value,
        meta=replace(value.meta, last_modified_date=NOW + timedelta(days=1), **changes[damage]),
    )
    feed = local_feed(tmp_path, snapshot("old"))
    with closing(sqlite3.connect(":memory:")) as connection:
        db = CVEdb(connection, [feed])
        list(db.data())
        before = _stored(db)
        with patch("cvedb.nvd.urllib.request.urlopen", side_effect=route(incoming)):
            with pytest.raises(ValueError, match="fixture"):
                db.reload(force=True)
        assert _stored(db) == before


@pytest.mark.parametrize("constant", ["_MAX_META_BYTES", "_MAX_GZIP_BYTES", "_MAX_JSON_BYTES"])
def test_upstream_caps_preserve_database(tmp_path: Path, constant: str) -> None:
    feed = local_feed(tmp_path, snapshot("old"))
    with closing(sqlite3.connect(":memory:")) as connection:
        db = CVEdb(connection, [feed])
        list(db.data())
        before = _stored(db)
        with (
            patch.object(nvd, constant, 8, create=True),
            patch("cvedb.nvd.urllib.request.urlopen", side_effect=route(snapshot("new"))),
        ):
            with pytest.raises(ValueError, match="fixture"):
                db.reload(force=True)
        assert _stored(db) == before


@pytest.mark.parametrize("error", [OSError("offline"), TimeoutError("socket timeout")])
def test_upstream_transport_failure_preserves_database(tmp_path: Path, error: OSError) -> None:
    feed = local_feed(tmp_path, snapshot("old"))
    with closing(sqlite3.connect(":memory:")) as connection:
        db = CVEdb(connection, [feed])
        list(db.data())
        before = _stored(db)
        with patch("cvedb.nvd.urllib.request.urlopen", side_effect=error):
            with pytest.raises(OSError, match="fixture"):
                db.reload(force=True)
        assert _stored(db) == before


def test_data_version_respects_empty_and_custom_parent_scopes(tmp_path: Path) -> None:
    from cvedb.feed import Data, DataSource, Feed

    class CustomFeed(Feed):
        register = False

        def reload(  # ty: ignore[missing-override-decorator]  # No override in Python 3.11.
            self, existing_data: Data | None = None
        ) -> DataSource:
            raise AssertionError("custom initialization")

    with closing(sqlite3.connect(":memory:")) as connection:
        other = CVEdb(connection, [local_feed(tmp_path, snapshot(), name="unrelated")])
        list(other.data())
        for parents in ([], [CustomFeed("custom")]):
            db = CVEdb(connection, parents)
            output = StringIO()
            with (
                patch("cvedb.cli.CVEdb.open", return_value=nullcontext(db)),
                patch("cvedb.cli.sys.stdout", output),
                patch("cvedb.nvd.urllib.request.urlopen", side_effect=AssertionError("network")),
            ):
                assert cli.main(["cvedb", "--data-version"]) == 0
            assert "Installed bundles for selected feeds: none" in output.getvalue()
            assert "unrelated" not in output.getvalue()


def test_failed_transfer_deadline_preserves_database_and_allows_retry(tmp_path: Path) -> None:
    from urllib.request import Request
    from test.feed_fixtures import Response

    clock = [0.0]

    def advance() -> None:
        clock[0] += 20

    feed = local_feed(tmp_path, snapshot("old"))
    incoming = snapshot("new")
    incoming = replace(
        incoming, meta=replace(incoming.meta, last_modified_date=NOW + timedelta(days=1))
    )
    body = Response(incoming.compressed, chunk_size=1, after_read=advance)

    def open_response(request: Request, *, timeout: float) -> Response:
        return Response(incoming.metadata()) if request.full_url.endswith(".meta") else body

    with closing(sqlite3.connect(":memory:")) as connection:
        db = CVEdb(connection, [feed])
        list(db.data())
        before = _stored(db)
        with (
            patch("cvedb.nvd.monotonic", side_effect=lambda: clock[0]),
            patch("cvedb.nvd.urllib.request.urlopen", side_effect=open_response),
        ):
            with pytest.raises(OSError, match="fixture.*deadline"):
                db.reload(force=True)
        assert _stored(db) == before
        assert body.stream.closed
        with patch("cvedb.nvd.urllib.request.urlopen", side_effect=route(incoming)):
            assert list(db.reload())[0].description() == "new"
        assert db.feeds[0].last_checked() is not None


def test_naive_metadata_timestamp_means_utc(tmp_path: Path) -> None:
    value = snapshot()
    feed = local_feed(tmp_path, value)
    feed.cached_meta_path.write_bytes(
        value.metadata().replace(NOW.isoformat().encode(), b"2020-01-02T00:00:00")
    )
    assert feed.data().last_modified_date == NOW


@pytest.mark.parametrize("missing", ["meta", "gzip", "both"])
def test_incomplete_bundle_pairs_remain_offline_and_unknown(tmp_path: Path, missing: str) -> None:
    feed = local_feed(tmp_path, snapshot())
    if missing in ("meta", "both"):
        feed.cached_meta_path.unlink()
    if missing in ("gzip", "both"):
        feed.cached_json_path.unlink()
    with patch("cvedb.nvd.urllib.request.urlopen", side_effect=AssertionError("network")):
        assert list(feed.data()) == []
        assert feed.data().last_modified_date is None


def test_report_uses_stored_counts_separately_from_installed_metadata(tmp_path: Path) -> None:
    feed = local_feed(tmp_path, snapshot(), name="2021")
    with CVEdb.open(tmp_path / "counts.sqlite", [feed]) as db:
        assert len(list(db.data())) == 1
        before = _stored(db)
        output = StringIO()
        with (
            patch("cvedb.cli.CVEdb.open", return_value=nullcontext(db)),
            patch.object(feed, "_load_initial", side_effect=AssertionError("initialization")),
            patch("cvedb.cli.sys.stdout", output),
        ):
            assert cli.main(["cvedb", "--data-version"]) == 0
        assert _stored(db) == before
        assert "2021" in output.getvalue()
        assert "2020-01-02" in output.getvalue()
        assert "never" in output.getvalue()


@pytest.mark.parametrize(
    "field", ["id", "assigner", "description", "language", "reference", "date", "surrogate"]
)
def test_invalid_consumed_cve_text_types_preserve_database(tmp_path: Path, field: str) -> None:
    import json

    document = json.loads(snapshot("new").raw)
    record = document["CVE_Items"][0]
    changes = {
        "id": lambda: record["cve"]["CVE_data_meta"].update(ID=123),
        "assigner": lambda: record["cve"]["CVE_data_meta"].update(ASSIGNER=123),
        "description": lambda: record["cve"]["description"]["description_data"][0].update(
            value=123
        ),
        "language": lambda: record["cve"]["description"]["description_data"][0].update(lang=123),
        "reference": lambda: record["cve"].update(references={"reference_data": [{"url": 123}]}),
        "date": lambda: record.update(publishedDate=123),
        "surrogate": lambda: record["cve"]["description"]["description_data"][0].update(
            value="\ud800"
        ),
    }
    changes[field]()
    incoming = snapshot(raw=json.dumps(document).encode())
    incoming = replace(
        incoming, meta=replace(incoming.meta, last_modified_date=NOW + timedelta(days=1))
    )
    feed = local_feed(tmp_path, snapshot("old"))
    with closing(sqlite3.connect(":memory:")) as connection:
        db = CVEdb(connection, [feed])
        list(db.data())
        before = _stored(db)
        with patch("cvedb.nvd.urllib.request.urlopen", side_effect=route(incoming)):
            with pytest.raises(ValueError, match="fixture"):
                db.reload(force=True)
        assert _stored(db) == before


def test_unreadable_bundle_fails_with_file_context_and_no_records(tmp_path: Path) -> None:
    feed = local_feed(tmp_path, snapshot())
    error = PermissionError("blocked")
    with closing(sqlite3.connect(":memory:")) as connection:
        db = CVEdb(connection, [feed])
        before = _stored(db)
        with patch.object(Path, "open", side_effect=error):
            with pytest.raises(OSError, match="fixture.meta") as caught:
                list(db.data())
        assert caught.value.__cause__ is error
        assert _stored(db) == before


def test_gzip_expanding_shorter_than_metadata_preserves_database(tmp_path: Path) -> None:
    value = snapshot("new")
    incoming = replace(
        value,
        meta=replace(
            value.meta, size=value.meta.size + 1, last_modified_date=NOW + timedelta(days=1)
        ),
    )
    feed = local_feed(tmp_path, snapshot("old"))
    with closing(sqlite3.connect(":memory:")) as connection:
        db = CVEdb(connection, [feed])
        list(db.data())
        before = _stored(db)
        with patch("cvedb.nvd.urllib.request.urlopen", side_effect=route(incoming)):
            with pytest.raises(ValueError, match="expanded snapshot.*fixture"):
                db.reload(force=True)
        assert _stored(db) == before


def test_naive_legacy_record_timestamps_mean_utc(tmp_path: Path) -> None:
    import json

    document = json.loads(snapshot().raw)
    record = document["CVE_Items"][0]
    record["publishedDate"] = "2020-01-02T00:00:00"
    record["lastModifiedDate"] = "2020-01-02T00:00:00"
    feed = local_feed(tmp_path, snapshot(raw=json.dumps(document).encode()))
    loaded = next(iter(feed.data()))
    assert loaded.published_date == NOW
    assert loaded.last_modified_date == NOW


def test_bundle_inspection_failure_has_file_context(tmp_path: Path) -> None:
    feed = local_feed(tmp_path, snapshot())
    error = PermissionError("blocked stat")
    with patch.object(Path, "stat", side_effect=error):
        with pytest.raises(OSError, match="fixture.json.gz") as caught:
            feed.data()
    assert caught.value.__cause__ is error
