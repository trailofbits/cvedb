from copy import deepcopy
from datetime import datetime, timezone
from typing import Any
from unittest.mock import patch

import pytest

from cvedb.cpe import parse_formatted_string
from cvedb.cve import CVE, Configurations, Severity
from cvedb.feed import FEEDS
from cvedb.nvd import JsonDataSource, Meta

TIMESTAMP = "2026-01-01T09:15:51.113Z"
EXPECTED_TIMESTAMP = datetime(2026, 1, 1, 9, 15, 51, 113000, tzinfo=timezone.utc)
CRITERIA = "cpe:2.3:a:example:widget:*:*:*:*:*:*:*:*"
VECTOR_V3 = "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
VECTOR_V2 = "AV:N/AC:L/Au:N/C:C/I:C/A:C"


def _feed() -> dict[str, Any]:
    return {
        "format": "NVD_CVE",
        "version": "2.0",
        "timestamp": TIMESTAMP,
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2026-1234",
                    "sourceIdentifier": "example@example.com",
                    "published": TIMESTAMP,
                    "lastModified": TIMESTAMP,
                    "descriptions": [{"lang": "en", "value": "English description"}],
                }
            }
        ],
    }


def _record(feed: dict[str, Any]) -> dict[str, Any]:
    return feed["vulnerabilities"][0]["cve"]


def _load(feed: dict[str, Any]) -> CVE:
    return next(iter(JsonDataSource.load(feed)))


def _node(**match: Any) -> dict[str, Any]:
    return {
        "operator": "OR",
        "cpeMatch": [
            {
                "vulnerable": True,
                "criteria": CRITERIA,
                **match,
            }
        ],
    }


def _matches(configurations: Configurations, version: str) -> bool:
    return configurations.match(
        parse_formatted_string(CRITERIA.replace("widget:*", f"widget:{version}"))
    )


def test_bundled_legacy_feed_loads_without_network() -> None:
    with patch(
        "cvedb.nvd.urllib.request.urlopen", side_effect=AssertionError("Unexpected network")
    ):
        source = FEEDS["2002"].reload()
    assert len(list(source)) > 0


def test_legacy_feed_preserves_records_and_timestamp() -> None:
    feed = {
        "CVE_data_timestamp": TIMESTAMP,
        "CVE_Items": [
            {
                "cve": {"CVE_data_meta": {"ID": "CVE-2026-1234"}},
                "publishedDate": TIMESTAMP,
                "lastModifiedDate": TIMESTAMP,
                "impact": {},
                "configurations": {"nodes": []},
            }
        ],
    }
    source = JsonDataSource.load(feed)
    assert [cve.cve_id for cve in source] == ["CVE-2026-1234"]
    assert source.last_modified_date == EXPECTED_TIMESTAMP


def test_schema_two_preserves_identity_references_and_timestamp_precision() -> None:
    feed = _feed()
    _record(feed)["references"] = [{"url": "https://example.com/advisory"}]
    original = deepcopy(feed)
    source = JsonDataSource.load(feed)
    cve = next(iter(source))
    assert cve.cve_id == "CVE-2026-1234"
    assert cve.assigner == "example@example.com"
    assert cve.references[0].url == "https://example.com/advisory"
    assert cve.published_date == EXPECTED_TIMESTAMP
    assert cve.last_modified_date == EXPECTED_TIMESTAMP
    assert source.last_modified_date == EXPECTED_TIMESTAMP
    assert feed == original


@pytest.mark.parametrize("timestamp", ["2026-01-01T09:15:51.113", "2026-01-01T10:15:51.113+01:00"])
def test_schema_two_timestamps_are_utc_and_preserve_offsets(timestamp: str) -> None:
    feed = _feed()
    feed["timestamp"] = timestamp
    _record(feed)["published"] = timestamp
    expected = datetime(2026, 1, 1, 9, 15, 51, 113000, tzinfo=timezone.utc)
    assert _load(feed).published_date == expected
    assert JsonDataSource.load(feed).last_modified_date == expected


def test_empty_schema_two_feed_and_supplied_metadata() -> None:
    meta = Meta(datetime(2026, 1, 1, tzinfo=timezone.utc), 0, 0, 0, b"")
    source = JsonDataSource.load({"vulnerabilities": []}, meta)
    assert len(source) == 0
    assert source.meta is meta


def test_missing_feed_timestamp_has_actionable_error() -> None:
    with pytest.raises(ValueError, match="must contain a timestamp"):
        JsonDataSource.load({"vulnerabilities": []})


def test_invalid_cve_timestamp_is_rejected() -> None:
    feed = _feed()
    _record(feed)["published"] = "not-a-date"
    with pytest.raises(ValueError):
        JsonDataSource.load(feed)


def test_invalid_configuration_operator_is_rejected() -> None:
    feed = _feed()
    _record(feed)["configurations"] = [{"operator": "XOR", "nodes": [_node()]}]
    with pytest.raises(NotImplementedError, match="operator 'XOR'"):
        JsonDataSource.load(feed)


@pytest.mark.parametrize("field", ["CVE_data_type", "CVE_data_format", "CVE_data_version"])
def test_invalid_legacy_schema_is_rejected(field: str) -> None:
    with pytest.raises(ValueError, match=f"Expected {field}"):
        JsonDataSource.load(
            {field: "unsupported", "CVE_data_timestamp": TIMESTAMP, "CVE_Items": []}
        )


@pytest.mark.parametrize("languages", [("en", "es", "fr"), ("es", "fr"), ()])
def test_all_description_languages_are_preserved(languages: tuple[str, ...]) -> None:
    feed = _feed()
    _record(feed)["descriptions"] = [
        {"lang": lang, "value": f"Description {lang}"} for lang in languages
    ]
    cve = _load(feed)
    assert len(cve.descriptions) == len(languages)
    for lang in languages:
        assert cve.description(lang) == f"Description {lang}"


@pytest.mark.parametrize(
    ("key", "boundary", "expected"),
    [
        ("versionStartIncluding", "3.0", (False, True, True)),
        ("versionStartExcluding", "3.0", (False, False, True)),
        ("versionEndIncluding", "3.0", (True, True, False)),
        ("versionEndExcluding", "3.0", (True, False, False)),
    ],
)
def test_cpe_version_boundaries(key: str, boundary: str, expected: tuple[bool, ...]) -> None:
    feed = _feed()
    _record(feed)["configurations"] = [{"nodes": [_node(**{key: boundary})]}]
    configurations = _load(feed).configurations
    assert tuple(_matches(configurations, v) for v in ("2.0", "3.0", "4.0")) == expected


def test_configuration_and_keeps_child_nodes_together() -> None:
    feed = _feed()
    _record(feed)["configurations"] = [
        {
            "operator": "AND",
            "nodes": [
                _node(),
                _node(criteria=CRITERIA.replace("widget:*", "widget:4.0")),
            ],
        }
    ]
    configurations = _load(feed).configurations
    assert not _matches(configurations, "3.0")
    assert _matches(configurations, "4.0")


def test_separate_configurations_remain_alternatives() -> None:
    feed = _feed()
    _record(feed)["configurations"] = [
        {"nodes": [_node(criteria=CRITERIA.replace("widget:*", "widget:2.0"))]},
        {"nodes": [_node(criteria=CRITERIA.replace("widget:*", "widget:4.0"))]},
    ]
    configurations = _load(feed).configurations
    assert _matches(configurations, "2.0")
    assert not _matches(configurations, "3.0")
    assert _matches(configurations, "4.0")


def test_non_vulnerable_operands_are_preserved() -> None:
    feed = _feed()
    _record(feed)["configurations"] = [
        {
            "operator": "AND",
            "nodes": [
                _node(),
                _node(vulnerable=False, criteria=CRITERIA.replace("widget:*", "widget:3.0")),
            ],
        }
    ]
    configurations = _load(feed).configurations
    assert _matches(configurations, "2.0")
    assert not _matches(configurations, "3.0")


def test_non_vulnerable_version_range_can_be_matched() -> None:
    feed = _feed()
    _record(feed)["configurations"] = [
        {
            "operator": "AND",
            "nodes": [
                _node(),
                _node(vulnerable=False, versionEndExcluding="4.0"),
            ],
        }
    ]
    configurations = _load(feed).configurations
    assert not _matches(configurations, "3.0")
    assert _matches(configurations, "4.0")


@pytest.mark.parametrize("level", ["configuration", "node"])
def test_schema_two_negation_is_preserved(level: str) -> None:
    feed = _feed()
    node = _node(criteria=CRITERIA.replace("widget:*", "widget:3.0"))
    configuration: dict[str, Any] = {"nodes": [node]}
    (configuration if level == "configuration" else node)["negate"] = True
    _record(feed)["configurations"] = [configuration]
    configurations = _load(feed).configurations
    assert _matches(configurations, "2.0")
    assert not _matches(configurations, "3.0")


@pytest.mark.parametrize(("version", "key"), [("3.1", "cvssMetricV31"), ("3.0", "cvssMetricV30")])
def test_cvss_three_assessments_are_used(version: str, key: str) -> None:
    feed = _feed()
    vector = f"CVSS:{version}/{VECTOR_V3}"
    _record(feed)["metrics"] = {key: [{"cvssData": {"vectorString": vector}}]}
    cve = _load(feed)
    assert cve.impact is not None
    assert cve.impact.vector == vector
    assert cve.severity == Severity.CRITICAL


def test_cvss_prefers_three_one_then_three_zero_then_two() -> None:
    feed = _feed()
    metrics = {
        "cvssMetricV31": [{"cvssData": {"vectorString": f"CVSS:3.1/{VECTOR_V3}"}}],
        "cvssMetricV30": [{"cvssData": {"vectorString": f"CVSS:3.0/{VECTOR_V3}"}}],
        "cvssMetricV2": [{"cvssData": {"vectorString": VECTOR_V2}}],
    }
    _record(feed)["metrics"] = metrics
    for key, vector in [
        ("cvssMetricV31", f"CVSS:3.1/{VECTOR_V3}"),
        ("cvssMetricV30", f"CVSS:3.0/{VECTOR_V3}"),
        ("cvssMetricV2", VECTOR_V2),
    ]:
        impact = _load(feed).impact
        assert impact is not None
        assert impact.vector == vector
        del metrics[key]
    assert _load(feed).severity == Severity.UNKNOWN


def test_cvss_prefers_nvd_source() -> None:
    feed = _feed()
    _record(feed)["metrics"] = {
        "cvssMetricV30": [
            {"source": "example.com", "cvssData": {"vectorString": "invalid"}},
            {"source": "nvd@nist.gov", "cvssData": {"vectorString": f"CVSS:3.0/{VECTOR_V3}"}},
        ]
    }
    assert _load(feed).severity == Severity.CRITICAL


def test_cve_without_assessments_or_configurations_loads() -> None:
    cve = _load(_feed())
    assert cve.severity == Severity.UNKNOWN
    assert not cve.configurations.match(parse_formatted_string(CRITERIA))
