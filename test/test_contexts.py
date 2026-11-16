"""Owned connection and nested transaction behavior."""

from collections.abc import Iterable
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
import sqlite3
from unittest.mock import Mock, patch

import pytest

from cvedb.cve import CVE
from cvedb.db import CVEdb
from cvedb.feed import Data, DataSource, Feed, InMemoryData
from cvedb.schemas import Schema

NOW = datetime(2020, 1, 2, tzinfo=timezone.utc)


class _Feed(Feed):
    register = False

    def __init__(self) -> None:
        super().__init__("contexts", InMemoryData(NOW, ()))

    def reload(  # ty: ignore[missing-override-decorator]  # Python 3.10 lacks override.
        self, existing_data: Data | None = None
    ) -> DataSource:
        return InMemoryData(NOW, ())


def _prepare(path: Path) -> None:
    with closing(sqlite3.connect(path)) as connection:
        Schema.open(connection)
        connection.commit()


def _add(db: CVEdb, number: int = 1) -> None:
    db.feeds[0].schema.add(CVE(f"CVE-2020-{number:04}", NOW, NOW), db.feeds[0].feed_id)


def test_nested_context_reuses_database_and_closes_at_outer_exit(tmp_path: Path) -> None:
    path = tmp_path / "nested.sqlite"
    context = CVEdb.open(path, [_Feed()])
    with context as outer:
        connection = outer.connection
        assert connection.in_transaction
        assert connection.execute("PRAGMA foreign_keys").fetchone()[0] == 1
        with context as inner:
            assert inner is outer
            assert inner.connection is connection
            _add(inner)
        assert connection.execute("SELECT COUNT(*) FROM cves").fetchone()[0] == 1
    with pytest.raises(sqlite3.ProgrammingError, match="closed"):
        connection.execute("SELECT 1")
    with closing(sqlite3.connect(path)) as reopened:
        assert reopened.execute("SELECT COUNT(*) FROM cves").fetchone()[0] == 1


@pytest.mark.parametrize("caught", [False, True])
def test_nested_failure_rolls_back_entire_outer_transaction(tmp_path: Path, caught: bool) -> None:
    path = tmp_path / "rollback.sqlite"
    _prepare(path)
    context = CVEdb.open(path, [_Feed()])
    if caught:
        with context as db:
            _add(db)
            with pytest.raises(RuntimeError, match="inner failure"):
                with context as inner:
                    _add(inner, 2)
                    raise RuntimeError("inner failure")
            _add(db, 3)
    else:
        with pytest.raises(RuntimeError, match="inner failure"):
            with context as db:
                _add(db)
                with context as inner:
                    _add(inner, 2)
                    raise RuntimeError("inner failure")
    with closing(sqlite3.connect(path)) as reopened:
        assert reopened.execute("SELECT COUNT(*) FROM cves").fetchone()[0] == 0
    with context as db:
        _add(db, 4)


def test_parent_generator_survives_repeated_context_use(tmp_path: Path) -> None:
    parent = _Feed()
    context = CVEdb.open(tmp_path / "repeat.sqlite", (feed for feed in [parent]))
    with context as first:
        first_connection = first.connection
        assert [feed.name for feed in first.feeds] == ["contexts"]
    with context as second:
        assert second.connection is not first_connection
        assert [feed.name for feed in second.feeds] == ["contexts"]


@pytest.mark.parametrize("parents", [[], iter(())])
def test_empty_parent_sets_initialize_and_query_without_network(
    tmp_path: Path, parents: Iterable[Feed]
) -> None:
    context = CVEdb.open(tmp_path / "empty.sqlite", parents)
    with patch("cvedb.nvd.urllib.request.urlopen", side_effect=AssertionError("network")):
        for _ in range(2):
            with context as db:
                assert len(db.data()) == 0
                assert list(db.data()) == []
                assert list(db.data().search("")) == []
                assert list(db.reload(force=True)) == []
                assert db.connection.execute("PRAGMA user_version").fetchone()[0] == 2


def test_connect_failure_leaves_context_reusable(tmp_path: Path) -> None:
    context = CVEdb.open(tmp_path / "connect.sqlite", [])
    with patch("cvedb.db.connect", side_effect=sqlite3.OperationalError("connect failure")):
        with pytest.raises(sqlite3.OperationalError, match="connect failure"):
            with context:
                pass
    with context as db:
        assert list(db.data()) == []


def test_initialization_failure_closes_connection_and_resets_context(tmp_path: Path) -> None:
    connection = sqlite3.connect(":memory:")
    context = CVEdb.open(tmp_path / "init.sqlite", [])
    with (
        patch("cvedb.db.connect", return_value=connection),
        patch("cvedb.db.Schema.open", side_effect=ValueError("schema failure")),
    ):
        with pytest.raises(ValueError, match="schema failure"):
            with context:
                pass
    with pytest.raises(sqlite3.ProgrammingError, match="closed"):
        connection.execute("SELECT 1")
    with context as db:
        assert len(db.data()) == 0


@pytest.mark.parametrize("operation", ["commit", "rollback", "close"])
def test_exit_failures_close_and_reset_context(tmp_path: Path, operation: str) -> None:
    connection = sqlite3.connect(":memory:")
    wrapped = Mock(spec=sqlite3.Connection, wraps=connection)
    if operation == "close":

        def fail_close() -> None:
            connection.close()
            raise sqlite3.OperationalError("close failure")

        wrapped.close.side_effect = fail_close
    else:
        getattr(wrapped, operation).side_effect = sqlite3.OperationalError(f"{operation} failure")
    context = CVEdb.open(tmp_path / "exit.sqlite", [])
    with patch("cvedb.db.connect", return_value=wrapped):
        with pytest.raises(sqlite3.OperationalError, match=f"{operation} failure"):
            with context:
                if operation == "rollback":
                    raise RuntimeError("body failure")
    with pytest.raises(sqlite3.ProgrammingError, match="closed"):
        connection.execute("SELECT 1")
    with context as db:
        assert len(db.data()) == 0


def test_constructor_does_not_commit_callers_existing_transaction() -> None:
    with closing(sqlite3.connect(":memory:")) as connection:
        Schema.open(connection)
        connection.execute("BEGIN")
        CVEdb(connection, [_Feed()])
        assert connection.in_transaction
        connection.rollback()
        assert connection.execute("SELECT COUNT(*) FROM feeds").fetchone()[0] == 0


def test_unentered_context_cannot_exit_and_remains_reusable(tmp_path: Path) -> None:
    context = CVEdb.open(tmp_path / "unentered.sqlite", [])
    with pytest.raises(RuntimeError, match="has not been entered"):
        context.__exit__(None, None, None)
    with context as db:
        assert len(db.data()) == 0
