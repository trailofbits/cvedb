"""Differential behavior tests for persistent and in-memory searches."""

from collections.abc import Generator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import replace
from datetime import datetime, timedelta, timezone, UTC
import sqlite3
from typing import cast

from cvss import CVSS3
from hypothesis import given, settings, strategies as st
from hypothesis.strategies import SearchStrategy
import pytest

from cvedb.cpe import And, CPE, CPEMatch, Negate, VersionRange
from cvedb.cve import CVE, Configurations, Description, Reference
from cvedb.db import CVEdb, CVEdbData
from cvedb.feed import Data, DataSource, Feed, InMemoryData
from cvedb.schemas import Schema, UnsupportedQueryError
from cvedb.search import (
    AfterModifiedDateQuery,
    AfterPublishedDateQuery,
    AndQuery,
    BeforeModifiedDateQuery,
    BeforePublishedDateQuery,
    CPEQuery,
    DescriptionQuery,
    EnvironmentQuery,
    OrQuery,
    SearchQuery,
    Sort,
    TermQuery,
)

NOW = datetime(2020, 1, 2, 12, 30, 0, 500000, tzinfo=UTC)


def _record(number: int = 1, /, **changes: object) -> CVE:
    value = CVE(f"CVE-2020-{number:04}", NOW, NOW, descriptions=(Description("en", "alpha"),))
    return replace(value, **changes)


class _FixtureFeed(Feed):
    register = False

    def __init__(self, records: tuple[CVE, ...], name: str = "search") -> None:
        super().__init__(name, InMemoryData(NOW, records))

    def reload(  # ty: ignore[missing-override-decorator]  # No override in Python 3.11.
        self, existing_data: Data | None = None
    ) -> DataSource:
        assert self._data is not None
        return self._data


@contextmanager
def _views(records: tuple[CVE, ...]) -> Generator[tuple[CVEdbData, InMemoryData], None, None]:
    connection = sqlite3.connect(":memory:")
    try:
        db = CVEdb(connection, [_FixtureFeed(records)])
        data = db.data()
        list(data)
        yield data, InMemoryData(NOW, records)
    finally:
        connection.close()


def _assert_parity(records: tuple[CVE, ...], query: SearchQuery, expected: list[CVE]) -> None:
    with _views(records) as (stored, memory):
        assert list(memory.search(query)) == expected
        assert list(stored.search(query)) == expected


@pytest.mark.parametrize("case_sensitive", [False, True])
@pytest.mark.parametrize(
    "changes",
    [
        {"cve_id": "needle"},
        {"descriptions": (Description("fr", "needle"),)},
        {"references": (Reference(url="https://needle"),)},
        {"references": (Reference(name="needle"),)},
        {"assigner": "needle"},
    ],
)
def test_every_searchable_field_matches_without_english(
    changes: dict[str, object], case_sensitive: bool
) -> None:
    record = (
        _record(descriptions=(), **changes) if "descriptions" not in changes else _record(**changes)
    )
    _assert_parity((record,), TermQuery("needle", case_sensitive=case_sensitive), [record])


@pytest.mark.parametrize("needle", ["ÄPFEL", "STRASSE", "cve-2020-0001"])
def test_case_insensitive_search_uses_unicode_casefold(needle: str) -> None:
    record = _record(descriptions=(Description("en", "äpfel Straße"),))
    _assert_parity((record,), TermQuery(needle), [record])


@pytest.mark.parametrize("needle", ["%", "_", "%_", "é", ""])
def test_literal_substrings_and_unicode_survive_sql_selection(needle: str) -> None:
    matching = _record(descriptions=(Description("en", "café %_"),))
    other = _record(2, descriptions=(Description("en", "different"),))
    expected = [matching, other] if needle == "" else [matching]
    _assert_parity((matching, other), TermQuery(needle), expected)


def test_description_query_excludes_other_searchable_fields() -> None:
    record = _record(assigner="needle", references=(Reference(name="needle"),))
    _assert_parity((record,), DescriptionQuery("needle"), [])


@pytest.mark.parametrize("reference", [Reference(), Reference(name="name"), Reference(url="url")])
@pytest.mark.parametrize("case_sensitive", [False, True])
def test_optional_reference_fields_never_crash(reference: Reference, case_sensitive: bool) -> None:
    record = _record(references=(reference,))
    _assert_parity((record,), TermQuery("absent", case_sensitive=case_sensitive), [])


@pytest.mark.parametrize(
    "query",
    [
        CPEQuery(vendor="acme", version="1.2"),
        OrQuery(TermQuery("alpha"), CPEQuery(vendor="other")),
        OrQuery(CPEQuery(vendor="acme"), CPEQuery(vendor="other")),
        AndQuery(TermQuery("alpha"), OrQuery(CPEQuery(vendor="acme"), TermQuery("missing"))),
        OrQuery(AndQuery(TermQuery("missing"), CPEQuery(vendor="other")), TermQuery("alpha")),
        AndQuery(OrQuery(), TermQuery("alpha")),
        OrQuery(AndQuery(), TermQuery("missing")),
    ],
)
def test_cpe_and_boolean_candidates_are_conservative(query: SearchQuery) -> None:
    record = _record(configurations=Configurations([CPE(vendor="acme")]))
    expected = [record] if query.matches(record) else []
    _assert_parity((record,), query, expected)


def test_ranges_negation_and_environment_queries_keep_configuration_semantics() -> None:
    app, platform = CPE(vendor="acme"), CPE(vendor="platform")
    criterion = VersionRange(app, start="1.0", end="3.0", include_end=False)
    configuration = Configurations([And([CPEMatch(criterion), CPEMatch(platform, False)])])
    record = _record(configurations=configuration)
    for query in (
        CPEQuery(vendor="acme", version="2.0"),
        CPEQuery(vendor="acme", version="4.0"),
        EnvironmentQuery([CPE(vendor="acme", version="2.0"), platform]),
        OrQuery(TermQuery("absent"), EnvironmentQuery([app, platform])),
        EnvironmentQuery([CPE(vendor="acme", version="2.0")]),
    ):
        _assert_parity((record,), query, [record] if query.matches(record) else [])
    negated = replace(record, configurations=Configurations([Negate(CPEMatch(app))]))
    _assert_parity((negated,), CPEQuery(vendor="acme"), [negated])


class _CustomQuery(SearchQuery):
    def matches(  # ty: ignore[missing-override-decorator]  # No override in Python 3.11.
        self, cve: CVE
    ) -> bool:
        return cve.cve_id.endswith("1")


class _CustomTerm(TermQuery):
    def matches(  # ty: ignore[missing-override-decorator]  # No override in Python 3.11.
        self, cve: CVE
    ) -> bool:
        return True


@pytest.mark.parametrize("combine", [AndQuery, OrQuery])
def test_singleton_and_nested_custom_queries_use_fallback(
    combine: type[AndQuery] | type[OrQuery],
) -> None:
    first, second = _record(), _record(2)
    query = combine(combine(_CustomQuery()))
    _assert_parity((first, second), query, [first])


def test_custom_builtin_subclass_cannot_be_prefiltered_as_its_parent() -> None:
    record = _record()
    _assert_parity((record,), _CustomTerm("absent"), [record])


def test_unsupported_query_is_selected_before_returning_the_iterator() -> None:
    with _views((_record(),)) as (stored, _):
        with pytest.raises(UnsupportedQueryError, match="Unsupported SQL query"):
            stored.schema.search(_CustomQuery(), db_data=stored)


def test_genuine_matcher_errors_propagate_from_iteration() -> None:
    class InvalidQuery(SearchQuery):
        def matches(  # ty: ignore[missing-override-decorator]  # No override in Python 3.11.
            self, cve: CVE
        ) -> bool:
            raise ValueError("genuine matcher failure")

    with _views((_record(),)) as (stored, _):
        results = stored.search(InvalidQuery())
        with pytest.raises(ValueError, match="genuine matcher failure"):
            next(results)


def test_search_keeps_matcher_execution_lazy() -> None:
    calls: list[str] = []

    class CountedQuery(TermQuery):
        def matches(  # ty: ignore[missing-override-decorator]  # No override in Python 3.11.
            self, cve: CVE
        ) -> bool:
            calls.append(cve.cve_id)
            return True

    with _views((_record(),)) as (stored, _):
        results = stored.search(CountedQuery("alpha"))
        assert calls == []
        assert next(results).cve_id == "CVE-2020-0001"
        assert calls == ["CVE-2020-0001"]


def test_database_errors_are_not_treated_as_unsupported_queries() -> None:
    with _views((_record(),)) as (stored, _):
        results = stored.search(TermQuery("alpha"))
        stored.connection.execute("DROP TABLE refs")
        with pytest.raises(sqlite3.OperationalError, match="refs"):
            next(results)


@pytest.mark.parametrize(
    "query_type",
    [
        BeforePublishedDateQuery,
        AfterPublishedDateQuery,
        BeforeModifiedDateQuery,
        AfterModifiedDateQuery,
    ],
)
@pytest.mark.parametrize(
    "when", [NOW, NOW.replace(tzinfo=None), NOW.astimezone(timezone(timedelta(hours=3)))]
)
def test_date_boundaries_are_inclusive_utc_instants(
    query_type: type[BeforePublishedDateQuery]
    | type[AfterPublishedDateQuery]
    | type[BeforeModifiedDateQuery]
    | type[AfterModifiedDateQuery],
    when: datetime,
) -> None:
    record = _record()
    _assert_parity((record,), query_type(when), [record])


def test_fractional_and_negative_timestamps_are_not_truncated() -> None:
    for when in (NOW, datetime(1969, 12, 31, 23, 59, 59, 500000, tzinfo=UTC)):
        record = _record(published_date=when, last_modified_date=when)
        for query in (BeforePublishedDateQuery(when), AfterModifiedDateQuery(when)):
            _assert_parity((record,), query, [record])
        _assert_parity((record,), BeforePublishedDateQuery(when - timedelta(microseconds=1)), [])


@pytest.mark.parametrize("ascending", [True, False])
@pytest.mark.parametrize(
    "sorts", [(Sort.DESCRIPTION,), (Sort.IMPACT,), (Sort.DESCRIPTION, Sort.IMPACT)]
)
def test_missing_and_multilingual_sort_values_match_sql(
    ascending: bool, sorts: tuple[Sort, ...]
) -> None:
    impact = CVSS3("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    records = (
        _record(1, descriptions=()),
        _record(2, descriptions=(Description("fr", "z"), Description("en", ""))),
        _record(3, descriptions=(Description("fr", "b"),), impact=impact),
        _record(4, descriptions=(Description("fr", "z"), Description("en", "a"))),
    )
    with _views(records) as (stored, memory):
        expected = list(memory.search(TermQuery(""), sort=sorts, ascending=ascending))
        assert list(stored.search(TermQuery(""), sort=iter(sorts), ascending=ascending)) == expected
        assert (
            list(stored.search(_CustomTerm(""), sort=iter(sorts), ascending=ascending)) == expected
        )


def test_empty_english_description_remains_the_sort_key() -> None:
    record = _record(descriptions=(Description("fr", "z"), Description("en", "")))
    assert Sort.DESCRIPTION.get_key(record) == ""


def test_timestamp_sorting_normalizes_mixed_naive_and_aware_records() -> None:
    records = (_record(), _record(2, published_date=NOW.replace(tzinfo=None)))
    with _views(records) as (stored, memory):
        assert [record.cve_id for record in stored.search("", sort=[Sort.PUBLISHED_DATE])] == [
            record.cve_id for record in memory.search("", sort=[Sort.PUBLISHED_DATE])
        ]


def test_nested_three_child_sql_compounds_retain_predicates_and_bind_order() -> None:
    first, second, third = _record(), _record(2), _record(3)
    query = AndQuery(
        OrQuery(TermQuery("0001"), TermQuery("0002"), TermQuery("0003")),
        AndQuery(TermQuery("alpha"), TermQuery("2020"), TermQuery("0002")),
        OrQuery(TermQuery("absent"), TermQuery("alpha"), TermQuery("other")),
    )
    _assert_parity((first, second, third), query, [second])


def test_data_sources_without_timestamps_cannot_be_ordered() -> None:
    missing = InMemoryData(None, [])
    present = InMemoryData(NOW, [])
    with pytest.raises(TypeError, match="without last-modified timestamps"):
        assert missing < present
    with pytest.raises(TypeError, match="without last-modified timestamps"):
        assert present < missing


def test_fresh_update_without_timestamp_preserves_previous_data() -> None:
    original = _record()
    parent = _FixtureFeed((original,))
    connection = sqlite3.connect(":memory:")
    try:
        db = CVEdb(connection, [parent])
        assert list(db.data()) == [original]
        previous = connection.execute("SELECT * FROM feeds").fetchall()
        parent._data = InMemoryData(None, [_record(2)])
        backed = db.feeds[0]
        with pytest.raises(ValueError, match="upstream source has no last-modified timestamp"):
            backed.reload(backed.data(), force=True)
        assert list(db.data()) == [original]
        assert connection.execute("SELECT * FROM feeds").fetchall() == previous
    finally:
        connection.close()


@pytest.mark.parametrize("query", [TermQuery("STRASSE"), DescriptionQuery("STRASSE")])
def test_unicode_casefold_is_shared_by_description_and_term_queries(query: TermQuery) -> None:
    record = _record(descriptions=(Description("en", "Straße"),))
    _assert_parity((record,), query, [record])


def test_corrupt_record_errors_are_deferred_and_not_retried_as_fallback() -> None:
    with _views((_record(),)) as (stored, _):
        results = stored.search(TermQuery("alpha"))
        stored.connection.execute("UPDATE cves SET configurations='?'")
        with pytest.raises(ValueError, match="Invalid stored configurations.*reimport"):
            next(results)


def test_custom_compound_subclass_uses_its_override_in_fallback() -> None:
    class CustomAnd(AndQuery):
        def matches(  # ty: ignore[missing-override-decorator]  # No override in Python 3.11.
            self, cve: CVE
        ) -> bool:
            return True

    record = _record()
    _assert_parity((record,), CustomAnd(TermQuery("absent")), [record])


def test_custom_date_subclass_uses_its_override_in_fallback() -> None:
    class CustomBefore(BeforePublishedDateQuery):
        def matches(  # ty: ignore[missing-override-decorator]  # No override in Python 3.11.
            self, cve: CVE
        ) -> bool:
            return True

    record = _record()
    _assert_parity((record,), CustomBefore(datetime(1900, 1, 1)), [record])


def test_text_child_lookups_do_not_leak_between_feeds() -> None:
    first = _record(descriptions=(), references=(Reference(name="first"),), assigner="source-a")
    second = _record(references=(Reference(url="https://second"),), assigner="source-b")
    connection = sqlite3.connect(":memory:")
    try:
        db = CVEdb(connection, [_FixtureFeed((first,), "a"), _FixtureFeed((second,), "b")])
        list(db.data())
        data = db.feeds[0].data()
        assert list(data.search("first")) == [first]
        assert list(data.search("source-a")) == [first]
        assert list(data.search("second")) == []
        assert list(data.search("source-b")) == []
        assert list(data.search("alpha")) == []
    finally:
        connection.close()


@pytest.mark.parametrize("ascending", [True, False])
def test_unknown_scores_and_ties_have_an_explicit_order(ascending: bool) -> None:
    zero = CVSS3("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N")
    records = (_record(3, impact=zero), _record(2), _record(1))
    expected = ["CVE-2020-0001", "CVE-2020-0002", "CVE-2020-0003"]
    if not ascending:
        expected.reverse()
    with _views(records) as (stored, memory):
        for view in (stored, memory):
            assert [
                record.cve_id for record in view.search("", sort=[Sort.IMPACT], ascending=ascending)
            ] == expected


_QUERY_LEAVES: tuple[SearchQuery, ...] = (
    TermQuery("alpha"),
    TermQuery("ÄPFEL"),
    DescriptionQuery("STRASSE"),
    TermQuery("absent"),
    CPEQuery(vendor="acme"),
    CPEQuery(vendor="other"),
    BeforePublishedDateQuery(NOW),
    _CustomQuery(),
)
_QUERY_STRATEGY: SearchStrategy[SearchQuery] = st.recursive(
    st.sampled_from(_QUERY_LEAVES),
    lambda children: st.one_of(
        st.lists(children, max_size=3).map(lambda queries: AndQuery(*queries)),
        st.lists(children, max_size=3).map(lambda queries: OrQuery(*queries)),
    ),
    max_leaves=12,
)


@settings(max_examples=60, derandomize=True, deadline=None)
@given(query=_QUERY_STRATEGY)
def test_generated_query_trees_preserve_sql_and_memory_results(query: SearchQuery) -> None:
    records = (
        _record(configurations=Configurations([CPE(vendor="acme")])),
        _record(2, descriptions=(), references=(Reference(name="Straße"),), assigner="source"),
        _record(
            3,
            descriptions=(Description("fr", "Äpfel Straße"),),
            configurations=Configurations([CPE(vendor="other")]),
        ),
    )
    with _views(records) as (stored, memory):
        assert list(stored.search(query)) == list(memory.search(query))


@pytest.mark.parametrize("query", [TermQuery("beta"), DescriptionQuery("beta")])
def test_lazy_sql_searches_can_be_interleaved_on_one_connection(query: TermQuery) -> None:
    first = _record(1)
    second = _record(2, descriptions=(Description("en", "beta"),))
    third = _record(3)
    with _views((first, second, third)) as (stored, _):
        results = stored.search(TermQuery(""))
        assert next(results) == first
        assert list(stored.search(query)) == [second]
        assert list(results) == [second, third]


def test_reopening_schema_and_database_does_not_replace_active_search_function() -> None:
    records = (_record(1), _record(2))
    with _views(records) as (stored, _):
        results = stored.search("alpha")
        assert isinstance(results, Generator)
        try:
            assert next(results) == records[0]
            reopened = Schema.open(stored.connection)
            assert reopened.connection is stored.connection
            other = CVEdb(stored.connection, [_FixtureFeed(records)])
            assert list(other.data().search("alpha")) == list(records)
            assert list(results) == [records[1]]
        finally:
            results.close()


def test_contains_registration_checks_exact_function_name_and_arity() -> None:
    connection = sqlite3.connect(":memory:")
    try:
        connection.create_function("cvedb_contains", 2, lambda left, right: "two arguments")
        connection.create_function("cvedb_contains_other", 3, lambda *args: 0)
        db = CVEdb(connection, [_FixtureFeed((_record(),))])
        assert list(db.data().search("alpha")) == [_record()]
        row = connection.execute("SELECT cvedb_contains(1, 2)").fetchone()
        assert row == ("two arguments",)
    finally:
        connection.close()


class _NoFunctionListConnection(sqlite3.Connection):
    def execute(  # ty: ignore[missing-override-decorator]  # Python 3.11 lacks override.
        self, sql: str, parameters: object = ()
    ) -> sqlite3.Cursor:
        if sql == "PRAGMA function_list":
            sql = "PRAGMA cvedb_unrecognized_function_list"
        values = cast(Sequence[object] | Mapping[str, object], parameters)
        return super().execute(sql, values)

    def create_function(  # ty: ignore[missing-override-decorator]  # Python 3.11 lacks override.
        self, name: str, narg: int, func: object, *, deterministic: bool = False
    ) -> None:
        raise AssertionError("Cannot register search functions without introspection")


def test_missing_function_introspection_uses_eager_memory_fallback() -> None:
    first = _record(descriptions=(Description("fr", "Straße"),))
    second = _record(2, descriptions=(Description("en", "beta"),))
    records = (first, second)
    connection = sqlite3.connect(":memory:", factory=_NoFunctionListConnection)
    try:
        db = CVEdb(connection, [_FixtureFeed(records)])
        stored = db.data()
        memory = InMemoryData(NOW, records)
        queries = (
            TermQuery("STRASSE"),
            DescriptionQuery("BETA"),
            OrQuery(TermQuery("strasse"), AndQuery(TermQuery("beta"), TermQuery("missing"))),
        )
        for query in queries:
            with pytest.raises(UnsupportedQueryError, match="function introspection"):
                stored.schema.search(query, db_data=stored)
            actual = list(stored.search(query, sort=[Sort.DESCRIPTION], ascending=False))
            expected = list(memory.search(query, sort=[Sort.DESCRIPTION], ascending=False))
            assert actual == expected
        assert list(CVEdb(connection, [_FixtureFeed(records)]).data().search("STRASSE")) == [first]
    finally:
        connection.close()


class _FunctionSetupFailureConnection(sqlite3.Connection):
    fail_introspection = False

    def execute(  # ty: ignore[missing-override-decorator]  # Python 3.11 lacks override.
        self, sql: str, parameters: object = ()
    ) -> sqlite3.Cursor:
        if self.fail_introspection and sql == "PRAGMA function_list":
            raise sqlite3.OperationalError("function introspection failure")
        values = cast(Sequence[object] | Mapping[str, object], parameters)
        return super().execute(sql, values)

    def create_function(  # ty: ignore[missing-override-decorator]  # Python 3.11 lacks override.
        self, name: str, narg: int, func: object, *, deterministic: bool = False
    ) -> None:
        raise sqlite3.OperationalError("function registration failure")


@pytest.mark.parametrize("failure", ["introspection", "registration"])
def test_real_function_setup_errors_propagate(failure: str) -> None:
    connection = sqlite3.connect(":memory:", factory=_FunctionSetupFailureConnection)
    assert isinstance(connection, _FunctionSetupFailureConnection)
    connection.fail_introspection = failure == "introspection"
    try:
        with pytest.raises(sqlite3.OperationalError, match=f"function {failure} failure"):
            Schema.open(connection)
    finally:
        connection.close()
