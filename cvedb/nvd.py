import itertools
import json
import sys
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from gzip import decompress
from importlib.metadata import version as package_version
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional, TextIO, Union

from cvss import CVSS2, CVSS3
from dateutil.parser import isoparse
from tqdm import tqdm

from cvedb.cpe import And, Negate, Or, Testable, VersionRange, parse_formatted_string
from cvedb.cve import CVE, Configurations, Description, Reference
from cvedb.feed import Data, DataSource, Feed

BASE_JSON_URL: str = "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-"

PRE_SEED_DATA_DIR: Path = Path(__file__).absolute().parent / "data"


def camel_to_underscore(text: str) -> str:
    def process(i: int, c: str):
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

    def __iter__(self) -> Iterator[CVE]:
        return iter(self.cves)

    def __len__(self):
        return len(self.cves)

    @staticmethod
    def _parse_config_node(node: Dict[str, Any]) -> Testable:
        if "cpe23Uri" in node:
            cpe = parse_formatted_string(node["cpe23Uri"])
            vs = node.get("versionStartExcluding", None)
            include_start = vs is None
            vs = node.get("versionStartIncluding", vs)
            ve = node.get("versionEndExcluding", None)
            include_end = ve is None
            ve = node.get("versionEndIncluding", ve)
            testable: Testable = cpe
            if vs is not None or ve is not None:
                testable = VersionRange(
                    cpe, start=vs, end=ve, include_start=include_start, include_end=include_end
                )
            if node.get("cpe_name"):
                raise NotImplementedError("Add support for cpe_name key with value")
            unhandled_keys = node.keys() - {
                "cpe23Uri",
                "vulnerable",
                "versionStartIncluding",
                "versionStartExcluding",
                "versionEndIncluding",
                "versionEndExcluding",
                "cpe_name",
            }
            if unhandled_keys:
                raise NotImplementedError(
                    f"Add support for CPE 23 URI node keys {unhandled_keys!r}"
                )
            if not node.get("vulnerable", True):
                return Negate(testable)
            return testable
        elif "operator" in node:
            op_class = {"AND": And, "OR": Or}.get(node["operator"].upper())
            if op_class is None:
                raise NotImplementedError(
                    f"Unimplemented CVE configuration node operator {node['operator']!r}"
                )
            return op_class(
                map(
                    JsonDataSource._parse_config_node,
                    itertools.chain(node.get("children", []), node.get("cpe_match", [])),
                ),
                negate=not node.get("vulnerable", True),
            )
        else:
            raise ValueError(f"Unknown configuration node type: {node!r}")

    @staticmethod
    def parse_configurations(config_dict: Dict[str, Any]) -> Configurations:
        if config_dict.get("CVE_data_version", "4.0") != "4.0":
            raise ValueError(
                f"Unsupported configuration CVE_data_version: {config_dict['CVE_data_version']}"
            )
        return Configurations(
            JsonDataSource._parse_config_node(node) for node in config_dict["nodes"]
        )

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
        timestamp = isoparse(value)
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
        matches = []
        for match in node.get("cpeMatch", []):
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
            "vulnerable": not node.get("negate", False),
            "children": [
                JsonDataSource._convert_config_node(child) for child in node.get("nodes", [])
            ],
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
            return req.read()
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

    def reload(self, existing_data: Optional[Data] = None) -> DataSource:
        if existing_data is None or len(existing_data) == 0:
            # Use the bundled feed for the first load when it is available.
            if self.cached_json_path.exists() and self.cached_meta_path.exists():
                with open(self.cached_meta_path, "r") as meta:
                    with open(self.cached_json_path, "rb") as compressed_json:
                        return JsonDataSource.load(
                            json.loads(decompress(compressed_json.read())), Meta.load(meta)
                        )
        with urllib.request.urlopen(self.meta_url) as req:
            new_meta = Meta.load(req)
        if (
            existing_data is not None
            and existing_data.last_modified_date is not None
            and new_meta.last_modified_date <= existing_data.last_modified_date
        ):
            # the existing data is newer
            return existing_data
        compressed = download(self.gz_url, new_meta.gz_size, sys.stderr.isatty())
        decompressed = decompress(compressed)
        data = json.loads(decompressed)
        return JsonDataSource.load(data, new_meta)


for year in range(2002, datetime.now().year + 1):
    JsonFeed(str(year))
