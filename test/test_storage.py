from contextlib import closing
from dataclasses import replace
from datetime import datetime, timezone, timedelta
from pathlib import Path
import sqlite3
from collections.abc import Iterator

import pytest

from cvedb.cpe import CPE, Language, Logical, Part
from cvedb.cve import CVE, Configurations, Description, Reference
from cvedb.db import CVEdb
from cvedb.feed import Feed, InMemoryData, Data, DataSource
from cvedb.schemas import Schema
from cvedb.search import CPEQuery

NOW = datetime(2026, 1, 1, 9, 15, 51, 113000, tzinfo=timezone.utc)
FULL_CPE = CPE(
    Part.APP,
    "acme",
    "widget",
    "1.2",
    "sp1",
    "pro",
    Language("en", "US"),
    "desktop",
    "linux",
    "x86",
    "custom",
)


@pytest.fixture
def schema() -> Iterator[Schema]:
    connection = sqlite3.connect(":memory:")
    try:
        yield Schema.open(connection)
    finally:
        connection.close()


def _record(
    *, description: str = "alpha", vendor: str = "acme", assigner: str | None = None
) -> CVE:
    return CVE(
        "CVE-2026-0001",
        NOW,
        NOW,
        descriptions=(Description("en", description),),
        references=(Reference("https://example/" + description, description),),
        assigner=assigner,
        configurations=Configurations([CPE(vendor=vendor)]),
    )


def _read(schema: Schema, feed: int) -> CVE:
    return next(
        schema.cve_iter(schema.connection.execute("SELECT * FROM cves WHERE feed=?", (feed,)))
    )


def test_feed_id_ignores_unrelated_last_insert(schema: Schema) -> None:
    first = schema.feed_id("first")
    second = schema.feed_id("second")
    schema.connection.execute("CREATE TABLE unrelated(value TEXT)")
    schema.connection.executemany("INSERT INTO unrelated VALUES (?)", [("a",), ("b",), ("c",)])
    assert schema.feed_id("first") == first
    assert schema.feed_id("second") == second
    assert first != second


def test_updates_replace_and_remove_child_records(schema: Schema) -> None:
    feed = schema.feed_id("source")
    schema.add(_record(), feed)
    changed = _record(description="new", vendor="other", assigner="new@example")
    schema.add(changed, feed)
    schema.add(changed, feed)
    assert _read(schema, feed) == changed
    assert schema.connection.execute("SELECT COUNT(*) FROM cpes").fetchone()[0] == 1
    empty = replace(changed, descriptions=(), references=(), configurations=Configurations([]))
    schema.add(empty, feed)
    assert _read(schema, feed) == empty
    assert schema.connection.execute("SELECT COUNT(*) FROM configurations").fetchone()[0] == 0
    assert schema.connection.execute("SELECT COUNT(*) FROM cpes").fetchone()[0] == 0


def test_overlapping_ids_remain_feed_scoped(schema: Schema) -> None:
    first, second = schema.feed_id("a"), schema.feed_id("b")
    a = _record(description="a", assigner="a@example")
    b = _record(description="b", vendor="other", assigner="b@example")
    schema.add(a, first)
    schema.add(b, second)
    assert _read(schema, first) == a
    assert _read(schema, second) == b
    schema.add(replace(a, descriptions=(), references=(), assigner=None), first)
    assert _read(schema, second) == b
    assert schema.connection.execute("PRAGMA foreign_key_check").fetchall() == []


def test_record_add_does_not_commit_outer_transaction(schema: Schema) -> None:
    feed = schema.feed_id("source")
    schema.connection.commit()
    with pytest.raises(RuntimeError, match="interrupted"):
        with schema.connection:
            schema.add(_record(), feed)
            schema.add(replace(_record(), cve_id="CVE-2026-0002"), feed)
            raise RuntimeError("interrupted")
    assert schema.connection.execute("SELECT COUNT(*) FROM cves").fetchone()[0] == 0


@pytest.mark.parametrize("table", ["descriptions", "refs", "configurations"])
def test_failed_child_insert_preserves_previous_record(schema: Schema, table: str) -> None:
    feed = schema.feed_id("source")
    previous = _record()
    schema.add(previous, feed)
    schema.connection.commit()
    schema.connection.execute(
        f"CREATE TRIGGER reject_child BEFORE INSERT ON {table} "
        "BEGIN SELECT RAISE(FAIL, 'child rejected'); END"
    )
    with pytest.raises(sqlite3.IntegrityError, match="child rejected"):
        schema.add(_record(description="changed", vendor="other"), feed)
    assert _read(schema, feed) == previous
    schema.connection.commit()
    assert _read(schema, feed) == previous


def test_schema_add_leaves_commit_with_caller(schema: Schema) -> None:
    feed = schema.feed_id("source")
    schema.connection.commit()
    schema.add(_record(), feed)
    assert schema.connection.in_transaction
    schema.connection.rollback()
    assert schema.connection.execute("SELECT COUNT(*) FROM cves").fetchone()[0] == 0


def test_assigner_and_ordered_metadata_survive_reopen(tmp_path: Path) -> None:
    path = tmp_path / "records.sqlite"
    record = replace(
        _record(assigner="source@example"),
        descriptions=(Description("fr", "bonjour"), Description("en", "hello")),
        references=(Reference(None, "name"), Reference("https://second", None)),
    )
    with closing(sqlite3.connect(path)) as connection, connection:
        schema = Schema.open(connection)
        feed = schema.feed_id("source")
        schema.add(record, feed)
    connection.close()
    with closing(sqlite3.connect(path)) as reopened:
        schema = Schema.open(reopened)
        assert schema.feed_id("source") == feed
        assert _read(schema, feed) == record
    reopened.close()


@pytest.mark.parametrize("version", [0, 1, 99])
def test_old_or_unknown_database_is_preserved(tmp_path: Path, version: int) -> None:
    path = tmp_path / "old.sqlite"
    connection = sqlite3.connect(path)
    connection.execute("CREATE TABLE cves(value TEXT)")
    connection.execute("INSERT INTO cves VALUES ('keep me')")
    connection.execute(f"PRAGMA user_version={version}")
    connection.commit()
    connection.close()
    original = path.read_bytes()
    with closing(sqlite3.connect(path)) as reopened:
        with pytest.raises(ValueError, match="separate|newer"):
            Schema.open(reopened)
        assert reopened.execute("SELECT * FROM cves").fetchall() == [("keep me",)]
    reopened.close()
    assert path.read_bytes() == original


@pytest.mark.parametrize(
    "value", [NOW, NOW.replace(tzinfo=None), NOW.astimezone(timezone(timedelta(hours=3)))]
)
def test_timestamp_round_trip_retains_instants_and_fractions(
    schema: Schema, value: datetime
) -> None:
    feed = schema.feed_id("source")
    schema.add(replace(_record(), published_date=value, last_modified_date=value), feed)
    restored = _read(schema, feed)
    assert restored.published_date == NOW
    assert restored.last_modified_date == NOW


class _LocalFeed(Feed):
    register = False

    def __init__(self, record: CVE) -> None:
        super().__init__("test")
        self.record = record

    def reload(  # ty: ignore[missing-override-decorator]  # No override in Python 3.10.
        self, existing_data: Data | None = None
    ) -> DataSource:
        return InMemoryData(NOW, [self.record])


@pytest.mark.parametrize(
    "field",
    [
        "part",
        "vendor",
        "product",
        "version",
        "update",
        "edition",
        "lang",
        "sw_edition",
        "target_sw",
        "target_hw",
        "other",
    ],
)
def test_every_cpe_component_can_be_persisted_and_searched(field: str) -> None:
    record = replace(_record(), configurations=Configurations([FULL_CPE]))
    with closing(sqlite3.connect(":memory:")) as connection:
        db = CVEdb(connection, [_LocalFeed(record)])
        query = CPEQuery(**{field: getattr(FULL_CPE, field)})
        assert list(db.data().search(query)) == [record]
        assert list(db.data())[0].configurations == record.configurations


@pytest.mark.parametrize("logical", [Logical.ANY, Logical.NA])
def test_logical_cpe_components_are_preserved(schema: Schema, logical: Logical) -> None:
    feed = schema.feed_id("source")
    value = CPE(part=logical, vendor=logical, lang=logical, target_hw=logical)
    record = replace(_record(), configurations=Configurations([value]))
    schema.add(record, feed)
    assert _read(schema, feed) == record


def test_shared_cpe_index_survives_other_records_update(schema: Schema) -> None:
    a, b = schema.feed_id("a"), schema.feed_id("b")
    original = _record()
    schema.add(original, a)
    schema.add(original, b)
    assert schema.connection.execute("SELECT COUNT(*) FROM cpes").fetchone()[0] == 1
    schema.add(_record(vendor="changed"), a)
    assert _read(schema, b) == original
    assert schema.connection.execute("SELECT COUNT(*) FROM cpes").fetchone()[0] == 2
    schema.add(replace(original, configurations=Configurations([])), b)
    assert schema.connection.execute("SELECT COUNT(*) FROM cpes").fetchone()[0] == 1


def test_foreign_keys_are_actually_enforced(schema: Schema) -> None:
    feed = schema.feed_id("source")
    assert schema.connection.execute("PRAGMA foreign_keys").fetchone()[0] == 1
    with pytest.raises(sqlite3.IntegrityError, match="FOREIGN KEY"):
        schema.connection.execute(
            "INSERT INTO refs VALUES (?, ?, ?, ?, ?)", ("missing", feed, 0, None, "https://example")
        )


def test_enabling_foreign_keys_does_not_commit_existing_transaction() -> None:
    with closing(sqlite3.connect(":memory:")) as connection:
        connection.execute("CREATE TABLE existing(value TEXT)")
        connection.execute("INSERT INTO existing VALUES ('uncommitted')")
        with pytest.raises(ValueError, match="finish the current transaction"):
            Schema.create(connection)
        assert connection.in_transaction
        connection.rollback()
        assert connection.execute("SELECT COUNT(*) FROM existing").fetchone()[0] == 0


def test_schema_creation_failure_rolls_back_partial_tables() -> None:
    with closing(sqlite3.connect(":memory:")) as connection:
        connection.execute("CREATE TABLE cpes(value TEXT)")
        with pytest.raises(sqlite3.OperationalError, match="already exists"):
            Schema.create(connection)
        assert connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall() == [("cpes",)]
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 0


def test_invalid_stored_impact_has_record_context(schema: Schema) -> None:
    feed = schema.feed_id("source")
    schema.add(_record(), feed)
    schema.connection.execute("UPDATE cves SET impact_vector='invalid'")
    with pytest.raises(ValueError, match="CVSS vector for CVE-2026-0001.*reimport"):
        _read(schema, feed)


@pytest.mark.parametrize("serialized", ["?", CPE().dumps()])
def test_invalid_stored_configurations_have_record_context(schema: Schema, serialized: str) -> None:
    feed = schema.feed_id("source")
    schema.add(_record(), feed)
    schema.connection.execute("UPDATE cves SET configurations=?", (serialized,))
    with pytest.raises(ValueError, match="configurations for CVE-2026-0001.*reimport"):
        _read(schema, feed)


class _OrderedSource(DataSource):
    def __init__(self, records: tuple[CVE, ...], timestamp: datetime) -> None:
        super().__init__(timestamp)
        self.records = records

    def __iter__(  # ty: ignore[missing-override-decorator]  # No override in Python 3.10.
        self,
    ) -> Iterator[CVE]:
        return iter(self.records)


class _MutableFeed(Feed):
    register = False

    def __init__(self, records: tuple[CVE, ...]) -> None:
        super().__init__("mutable")
        self.source = _OrderedSource(records, NOW)

    def reload(  # ty: ignore[missing-override-decorator]  # No override in Python 3.10.
        self, existing_data: Data | None = None
    ) -> DataSource:
        return self.source


def test_failed_second_cve_preserves_complete_feed_and_timestamps() -> None:
    original = _record()
    parent = _MutableFeed((original,))
    with closing(sqlite3.connect(":memory:")) as connection:
        db = CVEdb(connection, [parent])
        backed = db.feeds[0]
        backed.reload(force=True)
        before = connection.execute("SELECT last_modified, last_checked FROM feeds").fetchone()
        parent.source = _OrderedSource(
            (_record(description="changed"), replace(original, cve_id="CVE-2026-0002")),
            NOW + timedelta(days=1),
        )
        connection.execute(
            "CREATE TRIGGER reject_second BEFORE INSERT ON cves "
            "WHEN NEW.id='CVE-2026-0002' BEGIN SELECT RAISE(FAIL, 'second rejected'); END"
        )
        with pytest.raises(sqlite3.IntegrityError, match="second rejected"):
            backed.reload(backed.data(), force=True)
        assert list(backed.schema.cve_iter(connection.execute("SELECT * FROM cves"))) == [original]
        assert (
            connection.execute("SELECT last_modified, last_checked FROM feeds").fetchone() == before
        )


def test_environment_query_inside_or_does_not_lose_rows_without_descriptions() -> None:
    from cvedb.cpe import And, CPEMatch
    from cvedb.search import EnvironmentQuery, OrQuery, TermQuery

    app, platform = CPE(vendor="acme"), CPE(vendor="platform")
    record = replace(
        _record(),
        descriptions=(),
        configurations=Configurations([And([CPEMatch(app), CPEMatch(platform, False)])]),
    )
    with closing(sqlite3.connect(":memory:")) as connection:
        db = CVEdb(connection, [_LocalFeed(record)])
        inventory = EnvironmentQuery([app, platform])
        assert list(db.data().search(inventory)) == [record]
        assert list(db.data().search(OrQuery(TermQuery("missing"), inventory))) == [record]
        assert list(db.data().search(EnvironmentQuery([app]))) == []


def test_unloaded_persisted_view_retains_missing_timestamp_defense() -> None:
    from gzip import compress
    from hashlib import sha256
    from io import BytesIO
    from unittest.mock import patch
    from cvedb.feed import FEEDS
    from cvedb.nvd import Meta

    with closing(sqlite3.connect(":memory:")) as connection:
        db = CVEdb(connection, [_LocalFeed(_record())])
        view = db.data()
        payload = b'{"CVE_Items": []}'
        compressed = compress(payload, mtime=0)
        metadata = Meta(NOW, len(payload), 0, len(compressed), sha256(payload).digest())
        raw_metadata = (
            f"lastModifiedDate:{NOW.isoformat()}\nsize:{metadata.size}\nzipSize:0\n"
            f"gzSize:{metadata.gz_size}\nsha256:{metadata.sha256.hex()}\n"
        ).encode()
        with (
            patch("cvedb.nvd.urllib.request.urlopen", return_value=BytesIO(raw_metadata)),
            patch("cvedb.nvd.download", return_value=compressed),
        ):
            assert list(FEEDS["2022"].reload(view)) == []


def test_existing_feed_lookup_does_not_write_or_start_transaction(schema: Schema) -> None:
    feed = schema.feed_id("source")
    schema.connection.commit()
    changes = schema.connection.total_changes
    assert schema.feed_id("source") == feed
    assert schema.connection.total_changes == changes
    assert not schema.connection.in_transaction


def test_ignored_new_feed_insert_fails_with_name_context(schema: Schema) -> None:
    schema.connection.execute(
        "CREATE TRIGGER ignore_feed BEFORE INSERT ON feeds BEGIN SELECT RAISE(IGNORE); END"
    )
    with pytest.raises(ValueError, match="Cannot resolve feed 'source'"):
        schema.feed_id("source")


def test_ignored_cpe_insert_restores_record_atomically(schema: Schema) -> None:
    feed = schema.feed_id("source")
    previous = _record()
    schema.add(previous, feed)
    schema.connection.execute(
        "CREATE TRIGGER ignore_cpe BEFORE INSERT ON cpes BEGIN SELECT RAISE(IGNORE); END"
    )
    with pytest.raises(ValueError, match="Cannot resolve indexed CPE"):
        schema.add(_record(vendor="changed"), feed)
    assert _read(schema, feed) == previous


@pytest.mark.parametrize(
    "vector",
    [
        "AV:N/AC:L/Au:N/C:C/I:C/A:C",
        "AV:N/AC:L/Au:N/C:N/I:N/A:N",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
    ],
)
def test_supported_impact_vectors_and_severity_survive_storage(schema: Schema, vector: str) -> None:
    from cvss import CVSS2, CVSS3

    impact = CVSS3(vector) if vector.startswith("CVSS:3") else CVSS2(vector)
    record = replace(_record(), impact=impact)
    feed = schema.feed_id("source")
    schema.add(record, feed)
    restored = _read(schema, feed)
    assert restored.impact is not None
    assert restored.impact.vector == impact.vector
    assert restored.impact.base_score == impact.base_score
    assert restored.severity == record.severity
