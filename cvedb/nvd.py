from dataclasses import dataclass
from datetime import datetime
from gzip import decompress
import itertools
import json
import sys
from typing import Any, Dict, Iterable, Iterator, List, Optional, TextIO, Union
import urllib.request

from cvss import CVSS2, CVSS3
from dateutil.parser import isoparse
from tqdm import tqdm

from .cpe import And, Negate, Or, parse_formatted_string, Testable, VersionRange
from .cve import Configurations, CVE, Description, Reference
from .feed import Data, DataSource, Feed

BASE_JSON_URL: str = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-"


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
        kvs = {}
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
            value = line[first_colon+1:].decode("utf-8")
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
            if not node.get("vulnerable", True):
                cpe = Negate(cpe)
            vs = node.get("versionStartExcluding", None)
            include_start = vs is None
            vs = node.get("versionStartIncluding", vs)
            ve = node.get("versionEndExcluding", None)
            include_end = ve is None
            ve = node.get("versionEndIncluding", ve)
            if vs is not None or ve is not None:
                cpe = VersionRange(cpe, start=vs, end=ve, include_start=include_start, include_end=include_end)
            unhandled_keys = node.keys() - {"cpe23Uri", "vulnerable", "versionStartIncluding", "versionStartExcluding",
                                            "versionEndIncluding", "versionEndExcluding"}
            if unhandled_keys:
                raise NotImplementedError(f"Add support for CPE 23 URI node keys {unhandled_keys!r}")
            return cpe
        elif "operator" in node:
            if node["operator"].upper() == "AND":
                op_class = And
            elif node["operator"].upper() == "OR":
                op_class = Or
            else:
                raise NotImplementedError(f"Unimplemented CVE configuration node operator {node['operator']!r}")
            return op_class(
                map(JsonDataSource._parse_config_node,
                    itertools.chain(node.get("children", []), node.get("cpe_match", []))),
                negate=not node.get("vulnerable", True)
            )
        else:
            raise ValueError(f"Unknown configuration node type: {node!r}")

    @staticmethod
    def parse_configurations(config_dict: Dict[str, Any]) -> Configurations:
        if config_dict.get("CVE_data_version", "4.0") != "4.0":
            raise ValueError(f"Unsupported configuration CVE_data_version: {config_dict['CVE_data_version']}")
        return Configurations(JsonDataSource._parse_config_node(node) for node in config_dict["nodes"])

    @staticmethod
    def parse_cve(cve_obj: Dict[str, Any]) -> CVE:
        cve_id = cve_obj["cve"]["CVE_data_meta"]["ID"]
        assigner = cve_obj["cve"]["CVE_data_meta"].get("ASSIGNER", None)
        references = tuple(
            Reference(
                url=ref.get("url", None),
                name=ref.get("name", None)
            )
            for ref in cve_obj["cve"].get("references", {}).get("reference_data", [])
        )
        descriptions = tuple(
            Description(
                lang=desc["lang"],
                value=desc["value"]
            )
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
            configurations=JsonDataSource.parse_configurations(cve_obj.get("configurations", {}))
        )

    @staticmethod
    def load(json_obj: Dict[str, Any], meta: Optional[Meta] = None) -> "JsonDataSource":
        for key, expected in (("CVE_data_type", "CVE"), ("CVE_data_format", "MITRE"), ("CVE_data_version", "4.0")):
            if json_obj.get(key, expected) != expected:
                raise ValueError(f"Expected {key} to be {expected!r} but instead got {json_obj[key]!r}")
        if meta is None:
            if "CVE_data_timestamp" not in json_obj:
                raise ValueError("If `meta` is None, `json_obj[\"CVE_data_timestamp\"]` must contain a timestamp")
            meta = Meta(isoparse(json_obj["CVE_data_timestamp"]).astimezone(), 0, 0, 0, b"")
        return JsonDataSource(meta, (
            JsonDataSource.parse_cve(cve_obj) for cve_obj in json_obj.get("CVE_Items", ())
        ))


def download(url: str, size: Optional[int] = None, show_progress: bool = True) -> bytes:
    with urllib.request.urlopen(url) as req:
        if not show_progress:
            return req.read()
        ret = bytearray()
        filename = url[url.rfind("/")+1:]
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

    def reload(self, existing_data: Optional[Data] = None) -> DataSource:
        with urllib.request.urlopen(self.meta_url) as req:
            new_meta = Meta.load(req)
        if existing_data is not None and existing_data.last_modified_date is not None and \
                new_meta.last_modified_date <= existing_data.last_modified_date:
            # the existing data is newer
            return existing_data
        compressed = download(self.gz_url, new_meta.gz_size, sys.stderr.isatty())
        decompressed = decompress(compressed)
        data = json.loads(decompressed)
        return JsonDataSource.load(data, new_meta)


for year in range(2002, datetime.now().year + 1):
    JsonFeed(str(year))
