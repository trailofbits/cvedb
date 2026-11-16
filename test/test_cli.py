"""CLI argument, operation, ordering, and transaction behavior."""

from collections.abc import Generator, Iterable
from contextlib import closing
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from io import StringIO
from pathlib import Path
import sqlite3
from unittest.mock import MagicMock, patch

from cvss import CVSS3
import pytest

from cvedb import cli
from cvedb.cpe import CPE, Logical
from cvedb.cve import CVE, Configurations, Description
from cvedb.db import CVEdb
from cvedb.feed import Data, DataSource, Feed, InMemoryData
from cvedb.schemas import Schema
from cvedb.search import SearchQuery, Sort, TermQuery
from cvedb.sql import Select

NOW = datetime(2020, 1, 2, tzinfo=timezone.utc)
SORTS = {
    "cve": Sort.CVE_ID,
    "modified": Sort.LAST_MODIFIED_DATE,
    "published": Sort.PUBLISHED_DATE,
    "impact": Sort.IMPACT,
    "severity": Sort.SEVERITY,
}


def _record(number: int, text: str = "alpha") -> CVE:
    return CVE(
        f"CVE-2020-{number:04}",
        NOW + timedelta(days=3 - number),
        NOW + timedelta(days=number),
        descriptions=(Description("en", text),),
        configurations=Configurations([CPE(vendor="acme", version=str(number))]),
    )


class _Feed(Feed):
    register = False

    def __init__(self, records: tuple[CVE, ...]) -> None:
        super().__init__("cli-fixture", InMemoryData(NOW, records))
        self.source: DataSource = InMemoryData(NOW + timedelta(days=1), records)
        self.calls = 0
        self.error: BaseException | None = None

    def reload(  # ty: ignore[missing-override-decorator]  # Python 3.10 lacks override.
        self, existing_data: Data | None = None
    ) -> DataSource:
        self.calls += 1
        if self.error is not None:
            raise self.error
        return self.source


@dataclass
class Fixture:
    path: Path
    feed: _Feed
    records: tuple[CVE, ...]

    def stored(self) -> tuple[CVE, ...]:
        with closing(sqlite3.connect(self.path)) as connection:
            schema = Schema.open(connection)
            return tuple(schema.cve_iter(connection.execute("SELECT * FROM cves ORDER BY id")))

    def metadata(self) -> tuple[float | None, float | None]:
        with closing(sqlite3.connect(self.path)) as connection:
            modified, checked = connection.execute(
                "SELECT last_modified, last_checked FROM feeds WHERE name=?", (self.feed.name,)
            ).fetchone()
            return (
                None if modified is None else float(modified),
                None if checked is None else float(checked),
            )


@pytest.fixture
def local(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Fixture:
    high = CVSS3("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    zero = CVSS3("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N")
    records = (
        _record(1),
        replace(_record(2, "beta"), impact=high),
        replace(_record(3), impact=zero),
    )
    feed = _Feed(records)
    path = tmp_path / "isolated.sqlite"
    monkeypatch.setattr(cli, "DEFAULT_DB_PATH", path)
    monkeypatch.setattr("cvedb.db.FEEDS", {feed.name: feed})
    monkeypatch.setattr(
        "cvedb.nvd.urllib.request.urlopen", MagicMock(side_effect=AssertionError("network"))
    )
    return Fixture(path, feed, records)


@pytest.fixture
def captured(monkeypatch: pytest.MonkeyPatch) -> list[tuple[list[CVE], bool | None]]:
    calls: list[tuple[list[CVE], bool | None]] = []

    def capture(cves: Iterable[CVE], force_color: bool | None = None) -> None:
        calls.append((list(cves), force_color))

    monkeypatch.setattr(cli, "print_cves", capture)
    return calls


@pytest.mark.parametrize(
    "options", [[], ["--ansi"], ["--sort", "cve"], ["--descending"], ["--sort"]]
)
def test_update_only_exits_without_listing(
    local: Fixture, captured: list[tuple[list[CVE], bool | None]], options: list[str]
) -> None:
    assert cli.main(["cvedb", "--update", *options]) == 0
    assert local.feed.calls == 1
    assert captured == []
    assert len(local.stored()) == 3


@pytest.mark.parametrize(
    "filters",
    [
        ["alpha"],
        ["--before", "2030-01-01"],
        ["--after", "2010-01-01"],
        ["--vendor", "acme"],
        ["--vendor", "*"],
        ["--software-version", "*"],
        ["--software-version", "1"],
    ],
)
def test_update_with_explicit_filters_lists_after_updating(
    local: Fixture, captured: list[tuple[list[CVE], bool | None]], filters: list[str]
) -> None:
    assert cli.main(["cvedb", "--update", *filters]) == 0
    assert local.feed.calls == 1
    assert len(captured) == 1
    assert captured[0][0]


@pytest.mark.parametrize("sort", list(SORTS))
@pytest.mark.parametrize("descending", [False, True])
@pytest.mark.parametrize("filtered", [False, True])
def test_every_sort_and_ansi_option_works_with_and_without_filters(
    local: Fixture,
    captured: list[tuple[list[CVE], bool | None]],
    sort: str,
    descending: bool,
    filtered: bool,
) -> None:
    arguments = ["cvedb", *(["alpha"] if filtered else []), "--ansi", "--sort", sort]
    if descending:
        arguments.append("--descending")
    assert cli.main(arguments) == 0
    expected = list(
        InMemoryData(NOW, local.records).search(
            TermQuery("alpha" if filtered else ""), sort=[SORTS[sort]], ascending=not descending
        )
    )
    assert captured == [(expected, True)]


def test_common_listing_defaults_to_automatic_color(
    local: Fixture, captured: list[tuple[list[CVE], bool | None]]
) -> None:
    assert cli.main(["cvedb"]) == 0
    assert captured == [(list(local.records), None)]
    assert local.feed.calls == 0


def test_multiple_sort_keys_keep_the_requested_order(
    local: Fixture, captured: list[tuple[list[CVE], bool | None]]
) -> None:
    assert cli.main(["cvedb", "--sort", "impact", "modified", "--descending"]) == 0
    expected = list(
        InMemoryData(NOW, local.records).search(
            "", sort=[Sort.IMPACT, Sort.LAST_MODIFIED_DATE], ascending=False
        )
    )
    assert captured[0][0] == expected


def test_terms_are_or_grouped_then_and_combined_with_other_filters(
    local: Fixture, captured: list[tuple[list[CVE], bool | None]]
) -> None:
    assert cli.main(["cvedb", "alpha", "beta", "--software-version", "2"]) == 0
    assert captured[0][0] == [local.records[1]]


@pytest.mark.parametrize("option", ["--database", "--vendor", "--software-version"])
@pytest.mark.parametrize("following", [[], ["--ansi"]])
def test_missing_option_values_exit_before_database_access(
    local: Fixture, option: str, following: list[str]
) -> None:
    with patch("cvedb.cli.CVEdb.open") as opened, pytest.raises(SystemExit) as error:
        cli.main(["cvedb", option, *following])
    assert error.value.code == 2
    opened.assert_not_called()
    assert not (local.path.parent / "None").exists()


@pytest.mark.parametrize("value", ["*", "-"])
@pytest.mark.parametrize("option", ["--vendor", "--software-version"])
def test_logical_cpe_values_are_valid(
    local: Fixture, captured: list[tuple[list[CVE], bool | None]], option: str, value: str
) -> None:
    assert cli.parse_cpe_arg(value) == (Logical.ANY if value == "*" else Logical.NA)
    assert cli.main(["cvedb", option, value]) == 0
    assert len(captured) == 1


def test_explicit_database_path_with_spaces_is_used(
    local: Fixture, captured: list[tuple[list[CVE], bool | None]]
) -> None:
    path = local.path.parent / "a folder" / "records database.sqlite"
    assert cli.main(["cvedb", "--database", str(path)]) == 0
    assert path.exists()
    assert not local.path.exists()
    assert captured[0][0] == list(local.records)


@pytest.mark.parametrize(
    "error",
    [OSError("offline"), ValueError("invalid feed"), sqlite3.OperationalError("storage failed")],
)
def test_expected_update_failure_reports_context_without_listing(
    local: Fixture, captured: list[tuple[list[CVE], bool | None]], error: Exception
) -> None:
    with CVEdb.open(local.path) as database:
        list(database.data())
    before = local.stored()
    metadata = local.metadata()
    local.feed.error = error
    stderr = StringIO()
    with patch("cvedb.cli.sys.stderr", stderr):
        assert cli.main(["cvedb", "--update", "alpha"]) == 1
    assert "update" in stderr.getvalue().lower()
    assert str(local.path) in stderr.getvalue()
    assert str(error) in stderr.getvalue()
    assert captured == []
    assert local.stored() == before
    assert local.metadata() == metadata


def test_unexpected_programmer_errors_propagate(local: Fixture) -> None:
    local.feed.error = TypeError("programmer error")
    with pytest.raises(TypeError, match="programmer error"):
        cli.main(["cvedb", "--update"])


def test_update_data_version_reports_new_stored_counts_without_listing(
    local: Fixture, captured: list[tuple[list[CVE], bool | None]]
) -> None:
    output = StringIO()
    with patch("cvedb.cli.sys.stdout", output):
        assert cli.main(["cvedb", "--update", "--data-version"]) == 0
    assert local.feed.calls == 1
    assert "Stored CVEs" in output.getvalue()
    assert "Installed bundles for selected feeds: none" in output.getvalue()
    assert captured == []


def test_update_then_version_takes_precedence_over_report_and_listing(
    local: Fixture, captured: list[tuple[list[CVE], bool | None]]
) -> None:
    output = StringIO()
    with (
        patch("cvedb.cli.sys.stdout", output),
        patch("cvedb.cli.version", return_value="1.2.3"),
        patch("cvedb.cli._data_version_table", side_effect=AssertionError("report")),
    ):
        assert cli.main(["cvedb", "--update", "--version", "--data-version", "alpha"]) == 0
    assert local.feed.calls == 1
    assert output.getvalue() == "1.2.3\n"
    assert captured == []


def test_version_only_does_not_open_the_database(local: Fixture) -> None:
    output = StringIO()
    with patch("cvedb.cli.sys.stdout", output), patch("cvedb.cli.CVEdb.open") as opened:
        assert cli.main(["cvedb", "--version"]) == 0
    opened.assert_not_called()
    assert output.getvalue().strip()


def test_none_argv_uses_sys_argv(
    local: Fixture, captured: list[tuple[list[CVE], bool | None]]
) -> None:
    with patch("cvedb.cli.sys.argv", ["cvedb", "alpha"]):
        assert cli.main() == 0
    assert captured[0][0] == [local.records[0], local.records[2]]


@pytest.mark.parametrize("error_type", [BrokenPipeError, KeyboardInterrupt])
def test_successful_update_survives_listing_failure_and_closes_results_while_open(
    local: Fixture, error_type: type[BaseException]
) -> None:
    changed = replace(local.records[0], descriptions=(Description("en", "updated alpha"),))
    local.feed.source = InMemoryData(NOW + timedelta(days=1), (changed,))
    closed_while_open: list[bool] = []
    original = Schema._search_results

    def traced(schema: Schema, query: SearchQuery, select: Select) -> Generator[CVE, None, None]:
        try:
            yield from original(schema, query, select)
        finally:
            try:
                schema.connection.execute("SELECT 1").fetchone()
            except sqlite3.ProgrammingError:
                closed_while_open.append(False)
            else:
                closed_while_open.append(True)

    def interrupted(cves: Iterable[CVE], force_color: bool | None = None) -> None:
        assert next(iter(cves)).description() == "updated alpha"
        raise error_type()

    with (
        patch.object(Schema, "_search_results", traced),
        patch("cvedb.cli.print_cves", interrupted),
    ):
        assert cli.main(["cvedb", "--update", "alpha"]) == 1
    assert local.stored() == (changed,)
    modified, checked = local.metadata()
    assert modified == (NOW + timedelta(days=1)).timestamp()
    assert checked is not None
    assert closed_while_open == [True]


@pytest.mark.parametrize("error_type", [BrokenPipeError, KeyboardInterrupt])
def test_successful_update_survives_reporting_output_failure(
    local: Fixture, error_type: type[BaseException]
) -> None:
    changed = replace(local.records[0], descriptions=(Description("en", "updated"),))
    local.feed.source = InMemoryData(NOW + timedelta(days=1), (changed,))
    table = cli._data_version_table
    observed_counts: list[str] = []

    def observed(database: CVEdb) -> tuple[list[list[str]], str]:
        rows, summary = table(database)
        observed_counts.append(rows[1][-1])
        return rows, summary

    output = MagicMock()
    output.write.side_effect = error_type()
    with patch("cvedb.cli._data_version_table", observed), patch("cvedb.cli.sys.stdout", output):
        assert cli.main(["cvedb", "--update", "--data-version"]) == 1
    assert observed_counts == ["1"]
    assert local.stored() == (changed,)
    modified, checked = local.metadata()
    assert modified == (NOW + timedelta(days=1)).timestamp()
    assert checked is not None


@pytest.mark.parametrize("flags", [[], ["--update"], ["--data-version"]])
def test_database_open_errors_return_contextual_failures(
    local: Fixture, captured: list[tuple[list[CVE], bool | None]], flags: list[str]
) -> None:
    error = StringIO()
    with patch("cvedb.cli.sys.stderr", error):
        assert cli.main(["cvedb", "--database", str(local.path.parent), *flags]) == 1
    assert "Cannot open database" in error.getvalue()
    assert str(local.path.parent) in error.getvalue()
    assert captured == []


def test_old_schema_error_is_actionable_and_does_not_modify_the_file(local: Fixture) -> None:
    with closing(sqlite3.connect(local.path)) as connection:
        connection.execute("CREATE TABLE cves(value TEXT)")
        connection.execute("PRAGMA user_version=1")
        connection.commit()
    original = local.path.read_bytes()
    output = StringIO()
    with patch("cvedb.cli.sys.stderr", output):
        assert cli.main(["cvedb"]) == 1
    assert "separate database path" in output.getvalue()
    assert local.path.read_bytes() == original


@pytest.mark.parametrize("error_type", [TypeError, ValueError, RuntimeError])
def test_unexpected_renderer_errors_propagate(local: Fixture, error_type: type[Exception]) -> None:
    def broken(cves: Iterable[CVE], force_color: bool | None = None) -> None:
        next(iter(cves))
        raise error_type("unexpected renderer failure")

    with patch("cvedb.cli.print_cves", broken), pytest.raises(error_type, match="unexpected"):
        cli.main(["cvedb"])


def test_empty_feed_selection_has_a_successful_empty_listing(
    local: Fixture, captured: list[tuple[list[CVE], bool | None]], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("cvedb.db.FEEDS", {})
    assert cli.main(["cvedb"]) == 0
    assert captured == [([], None)]


def test_version_tty_keeps_its_prefix(local: Fixture) -> None:
    output = StringIO()
    with (
        patch("cvedb.cli.sys.stdout", output),
        patch.object(output, "isatty", return_value=True),
        patch("cvedb.cli.version", return_value="1.2.3"),
    ):
        assert cli.main(["cvedb", "--version"]) == 0
    assert output.getvalue() == "cvedb version 1.2.3\n"


def test_help_exits_before_database_access(local: Fixture) -> None:
    with patch("cvedb.cli.CVEdb.open") as opened, pytest.raises(SystemExit) as error:
        cli.main(["cvedb", "--help"])
    assert error.value.code == 0
    opened.assert_not_called()


def test_description_sort_is_not_added_as_a_cli_feature(local: Fixture) -> None:
    with patch("cvedb.cli.CVEdb.open") as opened, pytest.raises(SystemExit) as error:
        cli.main(["cvedb", "--sort", "description"])
    assert error.value.code == 2
    opened.assert_not_called()


def test_repeated_explicit_updates_bypass_throttling(
    local: Fixture, captured: list[tuple[list[CVE], bool | None]]
) -> None:
    assert cli.main(["cvedb", "--update"]) == 0
    assert cli.main(["cvedb", "--update"]) == 0
    assert local.feed.calls == 2
    assert captured == []


@pytest.mark.parametrize("field,value", [("impact_vector", "invalid"), ("configurations", "?")])
def test_invalid_stored_records_are_contextual_operational_failures(
    local: Fixture, field: str, value: str
) -> None:
    with CVEdb.open(local.path) as database:
        list(database.data())
    with closing(sqlite3.connect(local.path)) as connection:
        connection.execute(f"UPDATE cves SET {field}=?", (value,))
        connection.commit()
    output = StringIO()
    with patch("cvedb.cli.sys.stderr", output):
        assert cli.main(["cvedb"]) == 1
    assert "Cannot list database" in output.getvalue()
    assert str(local.path) in output.getvalue()
    assert "Invalid stored" in output.getvalue()


def test_corrupt_initial_bundle_is_an_operational_failure(
    local: Fixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    from test.feed_fixtures import local_feed, snapshot

    feed = local_feed(local.path.parent, snapshot())
    feed.cached_json_path.write_bytes(b"not gzip")
    monkeypatch.setattr("cvedb.db.FEEDS", {feed.name: feed})
    output = StringIO()
    with patch("cvedb.cli.sys.stderr", output):
        assert cli.main(["cvedb"]) == 1
    assert "Cannot list database" in output.getvalue()
    assert str(feed.cached_json_path) in output.getvalue()


@pytest.mark.parametrize("entry", ["module", "console"])
def test_closed_process_output_pipe_exits_without_flush_traceback(
    local: Fixture, entry: str
) -> None:
    from subprocess import PIPE, Popen
    import sys
    from cvedb.feed import FEEDS

    with closing(sqlite3.connect(local.path)) as connection:
        schema = Schema.open(connection)
        for name in FEEDS:
            feed = schema.feed_id(name)
            connection.execute(
                "UPDATE feeds SET last_modified=? WHERE id=?", (NOW.timestamp(), feed)
            )
        first_feed = schema.feed_id(next(iter(FEEDS)))
        for number in range(1, 1001):
            schema.add(_record(number, "a" * 4096), first_feed)
        connection.commit()
    command = (
        [sys.executable, "-m", "cvedb"]
        if entry == "module"
        else [str(Path(sys.executable).with_name("cvedb"))]
    )
    with Popen([*command, "--database", str(local.path)], stdout=PIPE, stderr=PIPE) as process:
        assert process.stdout is not None
        assert process.stdout.readline().startswith(b"CVE-")
        process.stdout.close()
        process.stdout = None
        _, errors = process.communicate(timeout=15)
        assert process.returncode == 1
    assert errors is not None
    assert b"Traceback" not in errors
    assert b"Exception ignored" not in errors


@pytest.mark.parametrize("error_type", [BrokenPipeError, KeyboardInterrupt])
def test_error_reporting_interruption_still_returns_failure(
    local: Fixture, error_type: type[BaseException]
) -> None:
    local.feed.error = ValueError("invalid feed")
    output = MagicMock()
    output.isatty.return_value = False
    output.write.side_effect = error_type()
    with patch("cvedb.cli.sys.stderr", output):
        assert cli.main(["cvedb", "--update"]) == 1


def test_entrypoint_flush_interruption_returns_failure(local: Fixture) -> None:
    from cvedb import __main__ as entry

    output = MagicMock()
    output.flush.side_effect = KeyboardInterrupt()
    with (
        patch.object(entry, "cli_main", return_value=0) as called,
        patch.object(entry.sys, "stdout", output),
    ):
        assert entry.main(["cvedb", "--version"]) == 1
    called.assert_called_once_with(["cvedb", "--version"])


def test_help_output_interruption_respects_argparse_behavior(local: Fixture) -> None:
    output = MagicMock()
    output.write.side_effect = BrokenPipeError()
    with patch("cvedb.cli.sys.stdout", output):
        try:
            status = cli.main(["cvedb", "--help"])
        except SystemExit as error:
            assert error.code == 0
        else:
            assert status == 1


@pytest.mark.parametrize("entry", ["module", "console"])
def test_help_on_a_preclosed_process_pipe_exits_without_a_traceback(
    local: Fixture, entry: str
) -> None:
    import os
    from subprocess import PIPE, Popen
    import sys

    command = (
        [sys.executable, "-m", "cvedb"]
        if entry == "module"
        else [str(Path(sys.executable).with_name("cvedb"))]
    )
    reader, writer = os.pipe()
    os.close(reader)
    try:
        with Popen([*command, "--help"], stdout=writer, stderr=PIPE) as process:
            _, errors = process.communicate(timeout=15)
            assert process.returncode == 1
    finally:
        os.close(writer)
    assert errors is not None
    assert b"Traceback" not in errors
    assert b"Exception ignored" not in errors
