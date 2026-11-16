from dataclasses import dataclass
from datetime import datetime
from gzip import decompress
from importlib.metadata import version as package_version
import itertools
import json
from pathlib import Path
import sys
from typing import Any, Dict, Iterable, Iterator, List, Optional, TextIO, Union
import urllib.request

from cvss import CVSS2, CVSS3
from dateutil.parser import isoparse
from tqdm import tqdm

from .cpe import And, Negate, Or, parse_formatted_string, Testable, VersionRange
from .cve import Configurations, CVE, Description, Reference
from .feed import Data, DataSource, Feed

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
            if node.get("cpe_name"):
                raise NotImplementedError("Add support for cpe_name key with value")
            unhandled_keys = node.keys() - {"cpe23Uri", "vulnerable", "versionStartIncluding", "versionStartExcluding",
                                            "versionEndIncluding", "versionEndExcluding", "cpe_name"}
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
    def two_to_one(json_obj: Dict[str, Any]) -> Dict[str, Any]:
        import json
        from datetime import datetime

        def convert_nvd_20_to_11(nvd_20_data):
            """
            Convert NVD 2.0 format to NVD 1.1 format
            """
            # Create the base structure for 1.1 format
            nvd_11_data = {
                "CVE_data_type": "CVE",
                "CVE_data_format": "MITRE",
                "CVE_data_version": "4.0",
                "CVE_data_numberOfCVEs": len(nvd_20_data.get("vulnerabilities", [])),
                "CVE_data_timestamp": convert_timestamp_format(nvd_20_data.get("timestamp", "")),
                "CVE_Items": []
            }
            
            # Convert each vulnerability
            for vuln in nvd_20_data.get("vulnerabilities", []):
                cve_item = convert_cve_item(vuln.get("cve", {}))
                nvd_11_data["CVE_Items"].append(cve_item)
            
            return nvd_11_data

        def convert_cve_item(cve_20):
            """
            Convert a single CVE item from 2.0 to 1.1 format
            """
            # Extract primary CVSS v3 and v2 metrics
            cvss_v3 = get_primary_cvss_v3(cve_20.get("metrics", {}))
            cvss_v2 = get_primary_cvss_v2(cve_20.get("metrics", {}))
            
            # Extract primary weakness
            primary_weakness = get_primary_weakness(cve_20.get("weaknesses", []))
            
            cve_item = {
                "cve": {
                    "data_type": "CVE",
                    "data_format": "MITRE",
                    "data_version": "4.0",
                    "CVE_data_meta": {
                        "ID": cve_20.get("id", ""),
                        "ASSIGNER": cve_20.get("sourceIdentifier", "")
                    },
                    "problemtype": convert_problemtype(primary_weakness),
                    "references": convert_references(cve_20.get("references", [])),
                    "description": convert_description(cve_20.get("descriptions", []))
                },
                "configurations": convert_configurations(cve_20.get("configurations", [])),
                "impact": convert_impact(cvss_v3, cvss_v2),
                "publishedDate": convert_date_format(cve_20.get("published", "")),
                "lastModifiedDate": convert_date_format(cve_20.get("lastModified", ""))
            }
            
            return cve_item

        def get_primary_cvss_v3(metrics):
            """
            Get primary CVSS v3 metric (prefer NVD source, fall back to first available)
            """
            cvss_v31 = metrics.get("cvssMetricV31", [])
            
            # Look for NVD source first
            for metric in cvss_v31:
                if metric.get("source") == "nvd@nist.gov":
                    return metric.get("cvssData", {})
            
            # Fall back to first available
            if cvss_v31:
                return cvss_v31[0].get("cvssData", {})
            
            return {}

        def get_primary_cvss_v2(metrics):
            """
            Get primary CVSS v2 metric (prefer NVD source, fall back to first available)
            """
            cvss_v2 = metrics.get("cvssMetricV2", [])
            
            # Look for NVD source first
            for metric in cvss_v2:
                if metric.get("source") == "nvd@nist.gov":
                    return metric.get("cvssData", {})
            
            # Fall back to first available
            if cvss_v2:
                return cvss_v2[0].get("cvssData", {})
            
            return {}

        def get_primary_weakness(weaknesses):
            """
            Get primary weakness (prefer NVD source, fall back to first available)
            """
            # Look for NVD source first
            for weakness in weaknesses:
                if weakness.get("source") == "nvd@nist.gov":
                    return weakness
            
            # Fall back to first available
            if weaknesses:
                return weaknesses[0]
            
            return {}

        def convert_problemtype(weakness):
            """
            Convert weaknesses to problemtype format
            """
            descriptions = weakness.get("description", [])
            
            problemtype_data = []
            if descriptions:
                description_list = []
                for desc in descriptions:
                    if desc.get("lang") == "en":
                        description_list.append({
                            "lang": "en",
                            "value": desc.get("value", "")
                        })
                
                if description_list:
                    problemtype_data.append({
                        "description": description_list
                    })
            else:
                # Fallback if no weaknesses found
                problemtype_data.append({
                    "description": [{
                        "lang": "en",
                        "value": "NVD-CWE-noinfo"
                    }]
                })
            
            return {
                "problemtype_data": problemtype_data
            }

        def convert_references(references_20):
            """
            Convert references from 2.0 to 1.1 format
            """
            reference_data = []
            
            for ref in references_20:
                url = ref.get("url", "")
                if not url:
                    continue
                    
                # Use the last part of URL as name if no better option
                name = url.split('/')[-1] if url else ""
                
                reference_data.append({
                    "url": url,
                    "name": name,
                    "refsource": ref.get("source", ""),
                    "tags": ref.get("tags", [])
                })
            
            return {
                "reference_data": reference_data
            }

        def convert_description(descriptions_20):
            """
            Convert descriptions from 2.0 to 1.1 format
            """
            description_data = []
            
            for desc in descriptions_20:
                if desc.get("lang") == "en":
                    description_data.append({
                        "lang": "en",
                        "value": desc.get("value", "")
                    })
            
            # Fallback if no English description
            if not description_data and descriptions_20:
                desc = descriptions_20[0]
                description_data.append({
                    "lang": desc.get("lang", "en"),
                    "value": desc.get("value", "")
                })
            
            return {
                "description_data": description_data
            }

        def convert_configurations(configurations_20):
            """
            Convert configurations from 2.0 to 1.1 format
            """
            nodes = []
            
            for config in configurations_20:
                for node in config.get("nodes", []):
                    cpe_matches = []
                    
                    for cpe_match in node.get("cpeMatch", []):
                        if cpe_match.get("vulnerable", False):
                            cpe_matches.append({
                                "vulnerable": True,
                                "cpe23Uri": cpe_match.get("criteria", ""),
                                "cpe_name": []  # Empty list as in 1.1 format
                            })
                    
                    if cpe_matches:
                        nodes.append({
                            "operator": node.get("operator", "OR"),
                            "children": [],
                            "cpe_match": cpe_matches
                        })
            
            return {
                "CVE_data_version": "4.0",
                "nodes": nodes
            }

        def convert_impact(cvss_v3, cvss_v2):
            """
            Convert CVSS metrics to impact section
            """
            impact = {}
            
            # Add CVSS v3 if available
            if cvss_v3:
                # Convert version from "3.1" to "3.0" for baseMetricV3
                cvss_v3_copy = cvss_v3.copy()
                if cvss_v3_copy.get("version") == "3.1":
                    cvss_v3_copy["version"] = "3.0"
                
                impact["baseMetricV3"] = {
                    "cvssV3": cvss_v3_copy,
                    "exploitabilityScore": 0.0,  # These would need to be calculated or extracted
                    "impactScore": 0.0
                }
            
            # Add CVSS v2 if available
            if cvss_v2:
                impact["baseMetricV2"] = {
                    "cvssV2": cvss_v2,
                    "severity": get_severity_from_score(cvss_v2.get("baseScore", 0.0)),
                    "exploitabilityScore": 0.0,
                    "impactScore": 0.0,
                    "obtainAllPrivilege": False,
                    "obtainUserPrivilege": False,
                    "obtainOtherPrivilege": False,
                    "userInteractionRequired": False
                }
            
            return impact

        def get_severity_from_score(score):
            """
            Convert CVSS base score to severity string
            """
            if score >= 9.0:
                return "CRITICAL"
            elif score >= 7.0:
                return "HIGH"
            elif score >= 4.0:
                return "MEDIUM"
            elif score > 0.0:
                return "LOW"
            else:
                return "NONE"

        def convert_date_format(date_str):
            """
            Convert date format from 2.0 to 1.1 format
            Example: "2026-01-01T09:15:51.113" -> "2026-01-01T09:15Z"
            """
            if not date_str:
                return ""
            
            try:
                # Parse the date string
                dt = datetime.fromisoformat(date_str.replace('Z', '+00:00'))
                # Format to 1.1 format (without microseconds, with Z)
                return dt.strftime("%Y-%m-%dT%H:%MZ")
            except (ValueError, AttributeError):
                return date_str

        def convert_timestamp_format(timestamp_str):
            """
            Convert timestamp format for top-level timestamp
            """
            return convert_date_format(timestamp_str)
        
        ret = convert_nvd_20_to_11(json_obj)
        return ret

    @staticmethod
    def load(json_obj: Dict[str, Any], meta: Optional[Meta] = None) -> "JsonDataSource":
        # do 2.0 to 1.1 convertion here
        json_obj = JsonDataSource.two_to_one(json_obj)
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
    cvedb_version = package_version("cvedb")
    request = urllib.request.Request(
        url=url,
        data=None,
        headers={
            "User-Agent":
                f"Mozilla/5.0 ({sys.platform}) AppleWebKit/605.1.15 (KHTML, like Gecko) CVEdb/{cvedb_version}"
        }
    )
    with urllib.request.urlopen(request) as req:
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
        self.cached_meta_path: Path = PRE_SEED_DATA_DIR / f"nvdcve-1.1-{self.name}.meta"
        self.cached_json_path: Path = PRE_SEED_DATA_DIR / f"nvdcve-1.1-{self.name}.json.gz"

    def reload(self, existing_data: Optional[Data] = None) -> DataSource:
        if existing_data is None or len(existing_data) == 0:
            # This is our first time loading this feed, so use the version shipped with CVEdb, if it exists:
            if self.cached_json_path.exists() and self.cached_meta_path.exists():
                with open(self.cached_meta_path, "r") as meta:
                    with open(self.cached_json_path, "rb") as compressed_json:
                        return JsonDataSource.load(json.loads(decompress(compressed_json.read())), Meta.load(meta))
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