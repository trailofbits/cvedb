from contextlib import closing
from datetime import datetime, timezone
import sqlite3
from io import StringIO

import pytest

from cvedb import cpe
from cvedb.cve import CVE, Configurations
from cvedb.nvd import JsonDataSource
from cvedb import search
from cvedb.sql import Or as SqlOr, SimpleQuery, TRUE

APP = cpe.CPE(vendor="acme", product="widget", version="3.0")
PLATFORM = cpe.CPE(vendor="platform", product="os", version="1.0")
OTHER = cpe.CPE(vendor="other", product="os", version="1.0")
NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


def _leaf(value: cpe.CPE, vulnerable: bool = True) -> dict[str, object]:
    return {"cpe23Uri": str(value), "vulnerable": vulnerable}


def _required_platform() -> Configurations:
    return JsonDataSource.parse_configurations(
        {"nodes": [{"operator": "AND", "cpe_match": [_leaf(APP), _leaf(PLATFORM, False)]}]}
    )


def test_required_platform_is_positive_requirement() -> None:
    configurations = _required_platform()
    assert not configurations.match(APP)
    assert not configurations.match(PLATFORM)
    assert configurations.match_inventory([APP, PLATFORM])
    assert not configurations.match_inventory([APP, OTHER])
    assert configurations.match_candidate(APP)
    assert not configurations.match_candidate(PLATFORM)


@pytest.mark.parametrize("operator", ["AND", "OR"])
@pytest.mark.parametrize("negate", [False, True])
def test_operator_negation_uses_explicit_flag(operator: str, negate: bool) -> None:
    expression = JsonDataSource._parse_config_node(
        {"operator": operator, "negate": negate, "cpe_match": [_leaf(APP)]}
    )
    assert expression.match(APP) is not negate
    assert expression.match(OTHER) is negate
    assert expression.match_inventory([APP]) is not negate
    assert expression.match_inventory([]) is negate


@pytest.mark.parametrize("configurations", [{}, {"nodes": []}])
def test_absent_configurations_do_not_match_every_product(
    configurations: dict[str, object],
) -> None:
    parsed = JsonDataSource.parse_configurations(configurations)
    assert len(parsed) == 0
    assert not parsed.match(APP)
    assert not parsed.match_inventory([APP])
    assert not parsed.match_candidate(APP)


@pytest.mark.parametrize("node", [{}, {"operator": "AND"}, {"operator": "OR", "cpe_match": "bad"}])
def test_malformed_populated_nodes_are_actionable(node: dict[str, object]) -> None:
    with pytest.raises((ValueError, TypeError), match="configuration|node|children|operands"):
        JsonDataSource.parse_configurations({"nodes": [node]})


def test_inventory_generators_and_multiple_platform_options() -> None:
    expression = Configurations(
        [
            cpe.And(
                [
                    cpe.CPEMatch(APP),
                    cpe.Or([cpe.CPEMatch(PLATFORM, False), cpe.CPEMatch(OTHER, False)]),
                ]
            )
        ]
    )
    assert expression.match_inventory(iter([APP, PLATFORM]))
    assert expression.match_inventory(iter([APP, OTHER]))
    assert not expression.match_inventory(iter([APP]))
    assert not expression.match_inventory(iter([PLATFORM]))


def test_candidates_retain_ranges_and_traverse_actual_negation() -> None:
    criterion = cpe.VersionRange(cpe.CPE(vendor="acme"), start="2", end="4", include_end=False)
    expression = Configurations([cpe.Negate(cpe.CPEMatch(criterion))])
    assert expression.match_candidate(APP)
    assert not expression.match_candidate(cpe.CPE(vendor="acme", version="5"))
    assert not expression.match(APP)
    assert expression.match_inventory([])
    assert not expression.match_inventory([APP])
    assert not Configurations([cpe.CPEMatch(APP, False)]).match_candidate(APP)


@pytest.mark.parametrize("wrapped", [APP, cpe.VersionRange(APP, start="2", end="4")])
@pytest.mark.parametrize("vulnerable", [False, True])
def test_marked_criteria_round_trip(wrapped: cpe.CPE | cpe.VersionRange, vulnerable: bool) -> None:
    original = cpe.CPEMatch(wrapped, vulnerable)
    restored = cpe.Testable.loads(original.dumps())
    assert original == restored
    assert original.match(APP) == restored.match(APP)
    assert original.match_inventory([APP, PLATFORM]) == restored.match_inventory([APP, PLATFORM])


def test_nested_configuration_round_trip_and_bare_candidates() -> None:
    original = Configurations([cpe.And([APP, cpe.CPEMatch(PLATFORM, False)]), cpe.Negate(OTHER)])
    restored = cpe.Testable.loads(original.dumps())
    assert restored == original
    assert restored.match_inventory([APP, PLATFORM])
    assert original.match_candidate(APP)
    assert not original.match_candidate(PLATFORM)
    assert Configurations([cpe.VersionRange(APP, start="2", end="4")]).match_candidate(APP)


def test_marked_criterion_rejects_invalid_serialized_mark_and_expression() -> None:
    with pytest.raises(ValueError, match="marker"):
        cpe.CPEMatch.load_content(StringIO("?" + APP.dumps()))
    with pytest.raises(ValueError, match="CPE|criterion"):
        cpe.CPEMatch.load_content(StringIO("1" + cpe.Or([APP]).dumps()))


def test_product_query_is_distinct_from_environment_query() -> None:
    record = CVE("CVE-2026-0001", NOW, NOW, configurations=_required_platform())
    assert search.CPEQuery(APP).matches(record)
    assert not search.EnvironmentQuery([APP]).matches(record)
    assert search.EnvironmentQuery(iter([APP, PLATFORM])).matches(record)


def test_sql_true_operand_is_preserved_under_or() -> None:
    with closing(sqlite3.connect(":memory:")) as connection:
        assert connection.execute(
            "SELECT " + SqlOr(SimpleQuery("0"), TRUE).to_sql()
        ).fetchone() == (1,)


@pytest.mark.parametrize(
    "extra",
    [
        {"vulnerable": "false"},
        {"versionStartIncluding": 3},
        {"cpe23Uri": None},
        {"versionStartIncluding": "1", "versionStartExcluding": "2"},
        {"unknown": True},
    ],
)
def test_malformed_criteria_are_rejected(extra: dict[str, object]) -> None:
    with pytest.raises(ValueError, match="configuration|Configuration"):
        JsonDataSource._parse_config_node({**_leaf(APP), **extra})


def test_generated_applicability_round_trips_preserve_matching() -> None:
    from hypothesis import given, settings, strategies as st

    leaves = st.one_of(
        st.sampled_from([APP, PLATFORM, OTHER]),
        st.builds(cpe.CPEMatch, st.sampled_from([APP, PLATFORM, OTHER]), st.booleans()),
        st.just(cpe.VersionRange(APP, start="2", end="4")),
    )
    trees = st.recursive(
        leaves,
        lambda child: st.one_of(
            st.builds(cpe.And, st.lists(child, min_size=1, max_size=3), st.booleans()),
            st.builds(cpe.Or, st.lists(child, min_size=1, max_size=3), st.booleans()),
            st.builds(cpe.Negate, child),
        ),
        max_leaves=10,
    )

    @given(trees)
    @settings(max_examples=75, derandomize=True, deadline=None)
    def verify(tree: cpe.Testable) -> None:
        original = Configurations([tree])
        restored = cpe.Testable.loads(original.dumps())
        assert isinstance(restored, Configurations)
        assert restored == original
        for inventory in ([], [APP], [APP, PLATFORM], [APP, OTHER]):
            assert restored.match_inventory(iter(inventory)) == original.match_inventory(inventory)
        for product in (APP, PLATFORM, OTHER):
            assert restored.match_candidate(product) == original.match_candidate(product)

    verify()


@pytest.mark.parametrize("node", [{"nodes": "bad"}, {"cpeMatch": "bad"}, {"cpeMatch": [{}]}])
def test_malformed_schema_two_nodes_are_actionable(node: dict[str, object]) -> None:
    with pytest.raises(ValueError, match="Configuration"):
        JsonDataSource._convert_config_node(node)


@pytest.mark.parametrize("absent", ["", None])
@pytest.mark.parametrize("side", ["Start", "End"])
def test_empty_legacy_bounds_preserve_exact_cpe_versions(absent: str | None, side: str) -> None:
    expression = JsonDataSource._parse_config_node(
        {**_leaf(APP), f"version{side}Including": absent, f"version{side}Excluding": absent}
    )
    assert expression.match(APP)
    assert not expression.match(cpe.CPE(vendor="acme", product="widget", version="4.0"))
    assert isinstance(expression, cpe.CPEMatch)
    assert isinstance(expression.criterion, cpe.CPE)


@pytest.mark.parametrize("absent", ["", None])
@pytest.mark.parametrize("included", [False, True])
@pytest.mark.parametrize("side", ["Start", "End"])
def test_absent_bound_does_not_override_meaningful_bound(
    absent: str | None, included: bool, side: str
) -> None:
    meaningful = f"version{side}{'Including' if included else 'Excluding'}"
    empty = f"version{side}{'Excluding' if included else 'Including'}"
    expression = JsonDataSource._parse_config_node(
        {**_leaf(cpe.CPE(vendor="acme")), meaningful: "3.0", empty: absent}
    )
    assert expression.match(APP) is included
    assert expression.match(cpe.CPE(vendor="acme", version="2.0")) is (side == "End")
    assert expression.match(cpe.CPE(vendor="acme", version="4.0")) is (side == "Start")


def test_bundled_cve_2015_7984_empty_start_retains_end_bound() -> None:
    uri = "cpe:2.3:a:horde:groupware:*:*:*:*:webmail:*:*:*"
    expression = JsonDataSource._parse_config_node(
        {
            "vulnerable": True,
            "cpe23Uri": uri,
            "versionStartIncluding": "",
            "versionEndExcluding": "5.2.11",
            "cpe_name": [],
        }
    )
    assert isinstance(expression, cpe.CPEMatch)
    assert isinstance(expression.criterion, cpe.VersionRange)
    assert expression.criterion.start is None
    assert expression.match(
        cpe.parse_formatted_string(uri.replace("groupware:*", "groupware:5.2.10"))
    )
    assert not expression.match(
        cpe.parse_formatted_string(uri.replace("groupware:*", "groupware:5.2.11"))
    )
