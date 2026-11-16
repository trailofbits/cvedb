import itertools
import json
import sys
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from gzip import decompress
from importlib.metadata import version as package_version
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional, TextIO, Union, cast

from cvss import CVSS2, CVSS3
from dateutil.parser import isoparse
from tqdm import tqdm

from cvedb.cpe import And, CPEMatch, Or, Testable, VersionRange, parse_formatted_string
from cvedb.cve import CVE, Configurations, Description, Reference
from cvedb.dates import utc_datetime
from cvedb.feed import Data, DataSource, Feed

_VERSION_BOUND_FIELDS = (
    "versionStartIncluding",
    "versionStartExcluding",
    "versionEndIncluding",
    "versionEndExcluding",
)
_CRITERION_FIELDS = {"cpe23Uri", "vulnerable", "cpe_name", *_VERSION_BOUND_FIELDS}

BASE_JSON_URL: str = "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-"

PRE_SEED_DATA_DIR: Path = Path(__file__).absolute().parent / "data"


def camel_to_underscore(text: str) -> str:
    def process(i: int, c: str) -> str:
        if i == 0:
            return c.lower()
        elif ord("A") <= ord(c) <= ord("Z"):
            return f"_{c.lower()}"
        else:
            return c

    return "".join(process(*v) for v in enumerate(text))


@dataclass(order=True, unsafe_hash=True, frozen=True)
class Meta:
    last_modified_date: datetime
    size: int
    zip_size: int
    gz_size: int
    sha256: bytes

    @staticmethod
    def loads(meta_str: Union[str, bytes]) -> "Meta":
        kvs: Dict[str, Any] = {}
        for line in meta_str.splitlines():
            if isinstance(line, str):
                line = line.encode("utf-8")
            if line.strip() == b"":
                continue
            first_colon = line.find(b":")
            if first_colon <= 0:
                raise ValueError(f"Unexpected line: {line!r}")
            key = camel_to_underscore(line[:first_colon].decode("utf-8"))
            if key in kvs:
                raise ValueError(f"Duplicate metadata key: {key!r}")
            value = line[first_colon + 1 :].decode("utf-8")
            if key == "last_modified_date":
                value = isoparse(value)
            elif key == "sha256":
                value = bytes.fromhex(value)
            else:
                value = int(value)
            kvs[key] = value
        return Meta(**kvs)

    @staticmethod
    def load(stream: TextIO) -> "Meta":
        return Meta.loads(stream.read())


class JsonDataSource(DataSource):
    def __init__(self, meta: Meta, cves: Iterable[CVE]):
        super().__init__(meta.last_modified_date)
        self.meta: Meta = meta
        if isinstance(cves, list):
            self.cves: List[CVE] = cves
        else:
            self.cves = list(cves)

    def __iter__(  # ty: ignore[missing-override-decorator]  # No override in Python 3.10.
        self,
    ) -> Iterator[CVE]:
        return iter(self.cves)

    def __len__(self):
        return len(self.cves)

    @staticmethod
    def _parse_version_bound(node: Dict[str, Any], edge: str) -> tuple[str | None, bool]:
        included, excluded = f"version{edge}Including", f"version{edge}Excluding"
        bounds: list[str | None] = []
        for key in (included, excluded):
            value = node.get(key)
            if value is not None and not isinstance(value, str):
                raise ValueError(f"Configuration {key} must be a string or absent")
            bounds.append(value or None)
        including, excluding = bounds
        if including is not None and excluding is not None:
            raise ValueError(f"Configuration criterion specifies both {included} and {excluded}")
        return (excluding, False) if excluding is not None else (including, True)

    @staticmethod
    def _parse_config_leaf(node: Dict[str, Any]) -> CPEMatch:
        value = node["cpe23Uri"]
        if not isinstance(value, str) or not value:
            raise ValueError("Configuration cpe23Uri must be a nonempty string")
        cpe = parse_formatted_string(value)
        start, include_start = JsonDataSource._parse_version_bound(node, "Start")
        end, include_end = JsonDataSource._parse_version_bound(node, "End")
        criterion = cpe
        if start is not None or end is not None:
            criterion = VersionRange(
                cpe,
                start=start,
                end=end,
                include_start=include_start,
                include_end=include_end,
            )
        if node.get("cpe_name"):
            raise NotImplementedError("Add support for cpe_name key with value")
        if node.keys() - _CRITERION_FIELDS:
            raise ValueError(
                f"Unsupported configuration criterion keys: {node.keys() - _CRITERION_FIELDS!r}"
            )
        vulnerable = node.get("vulnerable", True)
        if not isinstance(vulnerable, bool):
            raise ValueError("A configuration criterion's vulnerable mark must be a boolean")
        return CPEMatch(criterion, vulnerable)

    @staticmethod
    def _parse_config_node(node: Dict[str, Any]) -> Testable:
        if not isinstance(node, dict):
            raise ValueError("A configuration node must be an object")
        if "cpe23Uri" in node:
            return JsonDataSource._parse_config_leaf(node)
        operator = node.get("operator")
        if operator is None:
            raise ValueError(f"Unknown configuration node type: {node!r}")
        op_class = {"AND": And, "OR": Or}.get(str(operator).upper())
        if op_class is None:
            raise NotImplementedError(f"Unimplemented CVE configuration node operator {operator!r}")
        children, matches = node.get("children", []), node.get("cpe_match", [])
        if not isinstance(children, list) or not isinstance(matches, list):
            raise ValueError("Configuration node children and operands must be arrays")
        if not children and not matches:
            raise ValueError("A populated configuration node must contain children or operands")
        negate = node.get("negate", False)
        if not isinstance(negate, bool):
            raise ValueError("A configuration node's negate flag must be a boolean")
        return op_class(
            (
                JsonDataSource._parse_config_node(child)
                for child in itertools.chain(children, matches)
            ),
            negate=negate,
        )

    @staticmethod
    def parse_configurations(config_dict: Dict[str, Any]) -> Configurations:
        """Parse optional legacy configurations without inferring universal applicability."""
        if not isinstance(config_dict, dict):
            raise ValueError("CVE configurations must be an object")
        if config_dict.get("CVE_data_version", "4.0") != "4.0":
            raise ValueError(
                f"Unsupported configuration CVE_data_version: {config_dict['CVE_data_version']}"
            )
        nodes = config_dict.get("nodes", [])
        if not isinstance(nodes, list):
            raise ValueError("Configuration nodes must be an array")
        return Configurations(JsonDataSource._parse_config_node(node) for node in nodes)

    @staticmethod
    def parse_cve(cve_obj: Dict[str, Any]) -> CVE:
        cve_id = cve_obj["cve"]["CVE_data_meta"]["ID"]
        assigner = cve_obj["cve"]["CVE_data_meta"].get("ASSIGNER", None)
        references = tuple(
            Reference(url=ref.get("url", None), name=ref.get("name", None))
            for ref in cve_obj["cve"].get("references", {}).get("reference_data", [])
        )
        descriptions = tuple(
            Description(lang=desc["lang"], value=desc["value"])
            for desc in cve_obj["cve"].get("description", {}).get("description_data", [])
        )
        published_date = isoparse(cve_obj["publishedDate"])
        last_modified_date = isoparse(cve_obj["lastModifiedDate"])
        if "baseMetricV3" in cve_obj["impact"]:
            impact = CVSS3(cve_obj["impact"]["baseMetricV3"]["cvssV3"]["vectorString"])
        elif "baseMetricV2" in cve_obj["impact"]:
            impact = CVSS2(cve_obj["impact"]["baseMetricV2"]["cvssV2"]["vectorString"])
        else:
            impact = None
        return CVE(
            cve_id=cve_id,
            published_date=published_date,
            last_modified_date=last_modified_date,
            impact=impact,
            descriptions=descriptions,
            references=references,
            assigner=assigner,
            configurations=JsonDataSource.parse_configurations(cve_obj.get("configurations", {})),
        )

    @staticmethod
    def _convert_timestamp(value: str) -> str:
        timestamp = cast(datetime, isoparse(value))
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)
        return timestamp.isoformat()

    @staticmethod
    def _convert_impact(metrics: dict[str, Any]) -> dict[str, Any]:
        for key, base, data in (
            ("cvssMetricV31", "baseMetricV3", "cvssV3"),
            ("cvssMetricV30", "baseMetricV3", "cvssV3"),
            ("cvssMetricV2", "baseMetricV2", "cvssV2"),
        ):
            candidates = metrics.get(key, [])
            if candidates:
                metric = next(
                    (item for item in candidates if item.get("source") == "nvd@nist.gov"),
                    candidates[0],
                )
                return {base: {data: metric["cvssData"]}}
        return {}

    @staticmethod
    def _convert_config_node(node: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(node, dict):
            raise ValueError("A configuration node must be an object")
        children, criteria = node.get("nodes", []), node.get("cpeMatch", [])
        if not isinstance(children, list) or not isinstance(criteria, list):
            raise ValueError("Configuration node children and criteria must be arrays")
        matches = []
        for match in criteria:
            if not isinstance(match, dict) or "criteria" not in match or "vulnerable" not in match:
                raise ValueError("Configuration criteria require criteria and vulnerable fields")
            converted = {
                "vulnerable": match["vulnerable"],
                "cpe23Uri": match["criteria"],
            }
            for key in (
                "versionStartIncluding",
                "versionStartExcluding",
                "versionEndIncluding",
                "versionEndExcluding",
            ):
                if key in match:
                    converted[key] = match[key]
            matches.append(converted)
        return {
            "operator": node.get("operator", "OR"),
            "negate": node.get("negate", False),
            "children": [JsonDataSource._convert_config_node(child) for child in children],
            "cpe_match": matches,
        }

    @staticmethod
    def _convert_cve(cve: dict[str, Any]) -> dict[str, Any]:
        return {
            "cve": {
                "CVE_data_meta": {"ID": cve["id"], "ASSIGNER": cve.get("sourceIdentifier")},
                "description": {
                    "description_data": [
                        {"lang": desc["lang"], "value": desc["value"]}
                        for desc in cve.get("descriptions", [])
                    ]
                },
                "references": {
                    "reference_data": [
                        {"url": ref["url"], "name": ref["url"].rsplit("/", 1)[-1]}
                        for ref in cve.get("references", [])
                        if ref.get("url")
                    ]
                },
            },
            "configurations": {
                "nodes": [
                    JsonDataSource._convert_config_node(config)
                    for config in cve.get("configurations", [])
                ]
            },
            "impact": JsonDataSource._convert_impact(cve.get("metrics", {})),
            "publishedDate": JsonDataSource._convert_timestamp(cve["published"]),
            "lastModifiedDate": JsonDataSource._convert_timestamp(cve["lastModified"]),
        }

    @staticmethod
    def two_to_one(json_obj: dict[str, Any]) -> dict[str, Any]:
        """Adapt an NVD 2.0 feed for the existing NVD 1.1 parser.

        Args:
            json_obj: A decoded NVD 2.0 feed.

        Returns:
            A feed containing the fields consumed by the NVD 1.1 parser.
        """
        converted = {
            "CVE_data_type": "CVE",
            "CVE_data_format": "MITRE",
            "CVE_data_version": "4.0",
            "CVE_Items": [
                JsonDataSource._convert_cve(item["cve"]) for item in json_obj["vulnerabilities"]
            ],
        }
        if "timestamp" in json_obj:
            converted["CVE_data_timestamp"] = JsonDataSource._convert_timestamp(
                json_obj["timestamp"]
            )
        return converted

    @staticmethod
    def load(json_obj: Dict[str, Any], meta: Optional[Meta] = None) -> "JsonDataSource":
        if "vulnerabilities" in json_obj:
            json_obj = JsonDataSource.two_to_one(json_obj)
        for key, expected in (
            ("CVE_data_type", "CVE"),
            ("CVE_data_format", "MITRE"),
            ("CVE_data_version", "4.0"),
        ):
            if json_obj.get(key, expected) != expected:
                raise ValueError(
                    f"Expected {key} to be {expected!r} but instead got {json_obj[key]!r}"
                )
        if meta is None:
            if "CVE_data_timestamp" not in json_obj:
                raise ValueError(
                    'If `meta` is None, `json_obj["CVE_data_timestamp"]` must contain a timestamp'
                )
            meta = Meta(isoparse(json_obj["CVE_data_timestamp"]).astimezone(), 0, 0, 0, b"")
        return JsonDataSource(
            meta, (JsonDataSource.parse_cve(cve_obj) for cve_obj in json_obj.get("CVE_Items", ()))
        )


def download(url: str, size: Optional[int] = None, show_progress: bool = True) -> bytes:
    cvedb_version = package_version("cvedb")
    request = urllib.request.Request(
        url=url,
        data=None,
        headers={
            "User-Agent": (
                f"Mozilla/5.0 ({sys.platform}) AppleWebKit/605.1.15 "
                f"(KHTML, like Gecko) CVEdb/{cvedb_version}"
            )
        },
    )
    with urllib.request.urlopen(request) as req:
        if not show_progress:
            return cast(bytes, req.read())
        ret = bytearray()
        filename = url[url.rfind("/") + 1 :]
        with tqdm(desc=filename, unit=" b", leave=False) as t:
            if size is not None:
                t.total = size
            while True:
                chunk = req.read(65536)
                n = len(chunk)
                if n == 0:
                    break
                t.update(n)
                ret.extend(chunk)
        return bytes(ret)


class JsonFeed(Feed):
    def __init__(self, name: str, initial_data: Optional[Data] = None):
        super().__init__(name, initial_data)
        self.meta_url: str = f"{BASE_JSON_URL}{self.name}.meta"
        self.gz_url: str = f"{BASE_JSON_URL}{self.name}.json.gz"
        self.cached_meta_path: Path = PRE_SEED_DATA_DIR / f"nvdcve-1.1-{self.name}.meta"
        self.cached_json_path: Path = PRE_SEED_DATA_DIR / f"nvdcve-1.1-{self.name}.json.gz"

    def _load_initial(  # ty: ignore[missing-override-decorator]  # No override in Python 3.10.
        self,
    ) -> DataSource | None:
        if self._data is not None:
            return self._data
        if not self.cached_json_path.exists() or not self.cached_meta_path.exists():
            return None
        with self.cached_meta_path.open("r") as meta:
            with self.cached_json_path.open("rb") as compressed_json:
                return JsonDataSource.load(
                    json.loads(decompress(compressed_json.read())), Meta.load(meta)
                )

    def reload(  # ty: ignore[missing-override-decorator]  # No override in Python 3.10.
        self, existing_data: Optional[Data] = None
    ) -> DataSource:
        with urllib.request.urlopen(self.meta_url) as req:
            new_meta = Meta.load(req)
        last_modified = None if existing_data is None else existing_data.last_modified_date
        if (
            existing_data is not None
            and last_modified is not None
            and utc_datetime(new_meta.last_modified_date) <= utc_datetime(last_modified)
        ):
            # the existing data is newer
            return existing_data
        compressed = download(self.gz_url, new_meta.gz_size, sys.stderr.isatty())
        decompressed = decompress(compressed)
        data = json.loads(decompressed)
        return JsonDataSource.load(data, new_meta)


for year in range(2002, datetime.now().year + 1):
    JsonFeed(str(year))
