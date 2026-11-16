import itertools
import json
import sys
import urllib.request
import urllib.error
from collections.abc import Callable, Iterator
from dataclasses import dataclass, replace
from datetime import datetime
import gzip
from hashlib import sha256
import http.client
import io
from importlib.metadata import version as package_version
from pathlib import Path
from time import monotonic
import zlib
from typing import Any, Dict, Iterable, List, Optional, TextIO, Union, cast

from cvss import CVSS2, CVSS3, CVSSError
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

_MAX_META_BYTES = 64 * 1024
_MAX_GZIP_BYTES = 256 * 1024 * 1024
_MAX_JSON_BYTES = 2 * 1024 * 1024 * 1024
_MAX_JSON_DEPTH = 256
_SOCKET_TIMEOUT = 30
_TRANSFER_SECONDS = 300
_READ_CHUNK = 65536


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
                value = utc_datetime(cast(datetime, isoparse(value)))
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
        published_date = utc_datetime(cast(datetime, isoparse(cve_obj["publishedDate"])))
        last_modified_date = utc_datetime(cast(datetime, isoparse(cve_obj["lastModifiedDate"])))
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
        return utc_datetime(cast(datetime, isoparse(value))).isoformat()

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
            meta = Meta(
                utc_datetime(cast(datetime, isoparse(json_obj["CVE_data_timestamp"]))), 0, 0, 0, b""
            )
        return JsonDataSource(
            meta, (JsonDataSource.parse_cve(cve_obj) for cve_obj in json_obj.get("CVE_Items", ()))
        )


def _deadline(deadline: float | None, source: str) -> None:
    if deadline is not None and monotonic() >= deadline:
        raise TimeoutError(f"Transfer deadline exceeded while reading {source}")


def _read_limited(
    read: Callable[[int], object],
    limit: int,
    source: str,
    *,
    deadline: float | None = None,
    update: Callable[[int], object] | None = None,
) -> bytes:
    result = bytearray()
    while True:
        _deadline(deadline, source)
        chunk = read(min(_READ_CHUNK, limit - len(result) + 1))
        _deadline(deadline, source)
        if not isinstance(chunk, bytes):
            raise ValueError(f"Cannot read {source}: expected bytes from the input stream")
        if not chunk:
            return bytes(result)
        if len(result) + len(chunk) > limit:
            raise ValueError(f"Cannot read {source}: byte limit {limit} exceeded")
        result.extend(chunk)
        if update is not None:
            update(len(chunk))


def _check_length(actual: int, expected: int, source: str) -> None:
    if actual != expected:
        raise ValueError(
            f"Size mismatch for {source}: expected {expected} bytes, received {actual}"
        )


def _response_length(response: object, limit: int, source: str) -> int | None:
    headers = getattr(response, "headers", {})
    value = headers.get("Content-Length")
    if value is None:
        return None
    try:
        length = int(value)
    except (TypeError, ValueError) as error:
        raise ValueError(f"Invalid Content-Length while reading {source}: {value!r}") from error
    if not 0 <= length <= limit:
        raise ValueError(
            f"Cannot read {source}: declared length {length} exceeds byte limit {limit}"
        )
    return length


def _request(
    url: str,
    limit: int,
    *,
    expected: int | None = None,
    show_progress: bool = False,
) -> bytes:
    if expected is not None:
        if not 0 <= expected <= limit:
            raise ValueError(
                f"Cannot download {url}: declared size {expected} exceeds limit {limit}"
            )
        limit = min(limit, expected)
    deadline = monotonic() + _TRANSFER_SECONDS
    request = urllib.request.Request(
        url, headers={"User-Agent": f"CVEdb/{package_version('cvedb')} ({sys.platform})"}
    )
    try:
        with urllib.request.urlopen(request, timeout=_SOCKET_TIMEOUT) as response:
            declared = _response_length(response, limit, url)
            with tqdm(
                desc=url.rsplit("/", 1)[-1],
                unit=" b",
                leave=False,
                disable=not show_progress,
                total=expected or declared,
            ) as progress:
                data = _read_limited(
                    response.read1, limit, url, deadline=deadline, update=progress.update
                )
    except urllib.error.HTTPError as error:
        error.close()
        raise OSError(f"Cannot download {url}: {error}") from error
    except (OSError, http.client.HTTPException) as error:
        raise OSError(f"Cannot download {url}: {error}") from error
    if declared is not None:
        _check_length(len(data), declared, url)
    if expected is not None:
        _check_length(len(data), expected, url)
    return data


def download(url: str, size: Optional[int] = None, show_progress: bool = True) -> bytes:
    """Download a bounded feed body with explicit socket and transfer-loop timeouts.

    Args:
        url: The resource to download.
        size: The expected byte count, when known.
        show_progress: Whether to show download progress on stderr.

    Raises:
        ValueError: The declared or received size is invalid or exceeds a limit.
        OSError: The request, available-chunk read, or transfer deadline fails.
    """
    return _request(url, _MAX_GZIP_BYTES, expected=size, show_progress=show_progress)


def _read_file(path: Path, limit: int, *, expected: int | None = None) -> bytes:
    try:
        length = path.stat().st_size
        if length > limit:
            raise ValueError(f"Cannot read {path}: file size {length} exceeds byte limit {limit}")
        if expected is not None:
            _check_length(length, expected, str(path))
        with path.open("rb") as stream:
            read_limit = limit if expected is None else min(limit, expected)
            data = _read_limited(stream.read, read_limit, str(path))
    except OSError as error:
        raise OSError(f"Cannot read bundled snapshot file {path}: {error}") from error
    if expected is not None:
        _check_length(len(data), expected, str(path))
    return data


def _snapshot_meta(data: bytes, source: str) -> Meta:
    try:
        meta = Meta.loads(data)
        if len(meta.sha256) != 32:
            raise ValueError("sha256 must contain exactly 32 bytes")
        for name, value, limit in (
            ("size", meta.size, _MAX_JSON_BYTES),
            ("gzSize", meta.gz_size, _MAX_GZIP_BYTES),
        ):
            if not 0 < value <= limit:
                raise ValueError(f"{name} must be positive and at most {limit} bytes")
        if meta.zip_size < 0:
            raise ValueError("zipSize must be nonnegative")
        return replace(meta, last_modified_date=utc_datetime(meta.last_modified_date))
    except (ValueError, TypeError, OverflowError) as error:
        raise ValueError(f"Cannot parse snapshot metadata {source}: {error}") from error


def _expand_snapshot(data: bytes, meta: Meta, source: str) -> bytes:
    _check_length(len(data), meta.gz_size, source)
    try:
        with io.BytesIO(data) as compressed, gzip.GzipFile(fileobj=compressed, mode="rb") as stream:
            payload = _read_limited(
                stream.read, min(meta.size, _MAX_JSON_BYTES), f"expanded snapshot {source}"
            )
    except (OSError, EOFError, zlib.error) as error:
        raise ValueError(f"Cannot decompress snapshot {source}: {error}") from error
    _check_length(len(payload), meta.size, f"expanded snapshot {source}")
    if sha256(payload).digest() != meta.sha256:
        raise ValueError(f"SHA-256 mismatch for snapshot {source}; install a valid bundle or retry")
    return payload


def _validate_nesting(document: object) -> None:
    frames: list[tuple[Iterator[object], int]] = [(iter((document,)), 0)]
    while frames:
        iterator, parent_depth = frames[-1]
        try:
            value = next(iterator)
        except StopIteration:
            frames.pop()
            continue
        if isinstance(value, dict):
            children = iter(value.values())
        elif isinstance(value, list):
            children = iter(value)
        else:
            continue
        depth = parent_depth + 1
        if depth > _MAX_JSON_DEPTH:
            raise ValueError(f"JSON nesting exceeds {_MAX_JSON_DEPTH} container levels")
        frames.append((children, depth))


def _record_object(value: object, field: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ValueError(f"CVE {field} must be an object")
    return cast(dict[str, object], value)


def _record_text(value: object, field: str, *, optional: bool = False) -> None:
    if value is None and optional:
        return
    if not isinstance(value, str):
        raise ValueError(f"CVE {field} must be a string")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as error:
        raise ValueError(f"CVE {field} must contain valid UTF-8 text") from error


def _text_rows(value: object, fields: tuple[str, ...], *, optional: bool = False) -> None:
    if not isinstance(value, list):
        raise ValueError(f"CVE {fields!r} entries must be an array")
    for item in value:
        row = _record_object(item, "text entry")
        for field in fields:
            _record_text(row.get(field), field, optional=optional)


def _validate_records(document: dict[str, object]) -> None:
    records = document.get("CVE_Items")
    if not isinstance(records, list):
        raise ValueError("CVE_Items must be an array")
    for value in records:
        item = _record_object(value, "item")
        cve = _record_object(item.get("cve"), "record")
        metadata = _record_object(cve.get("CVE_data_meta"), "metadata")
        identity = metadata.get("ID")
        if not isinstance(identity, str) or not identity:
            raise ValueError("CVE ID must be a nonempty string")
        _record_text(identity, "ID")
        _record_text(metadata.get("ASSIGNER"), "ASSIGNER", optional=True)
        for field in ("publishedDate", "lastModifiedDate"):
            _record_text(item.get(field), field)
        descriptions = _record_object(cve.get("description", {}), "description")
        _text_rows(descriptions.get("description_data", []), ("lang", "value"))
        references = _record_object(cve.get("references", {}), "references")
        _text_rows(references.get("reference_data", []), ("name", "url"), optional=True)


def _invalid_json_constant(value: str) -> object:
    raise ValueError(f"Non-JSON numeric constant {value!r}")


def _load_snapshot(data: bytes, meta: Meta, source: str) -> JsonDataSource:
    payload = _expand_snapshot(data, meta, source)
    try:
        document = json.loads(payload, parse_constant=_invalid_json_constant)
        if not isinstance(document, dict):
            raise ValueError("the JSON root must be an object")
        _validate_nesting(document)
        collection = "vulnerabilities" if "vulnerabilities" in document else "CVE_Items"
        if not isinstance(document.get(collection), list):
            raise ValueError(f"{collection} must be an array")
        if collection == "vulnerabilities":
            document = JsonDataSource.two_to_one(document)
        _validate_records(document)
        return JsonDataSource.load(document, meta)
    except (
        ValueError,
        TypeError,
        KeyError,
        IndexError,
        AttributeError,
        RecursionError,
        OverflowError,
        NotImplementedError,
        CVSSError,
    ) as error:
        raise ValueError(f"Cannot parse snapshot {source}: {error}") from error


class JsonFeed(Feed):
    def __init__(self, name: str, initial_data: Optional[Data] = None):
        super().__init__(name, initial_data)
        self.meta_url: str = f"{BASE_JSON_URL}{self.name}.meta"
        self.gz_url: str = f"{BASE_JSON_URL}{self.name}.json.gz"
        self.cached_meta_path: Path = PRE_SEED_DATA_DIR / f"nvdcve-1.1-{self.name}.meta"
        self.cached_json_path: Path = PRE_SEED_DATA_DIR / f"nvdcve-1.1-{self.name}.json.gz"

    def _installed_meta(self) -> Meta | None:
        try:
            if not self.cached_json_path.exists() or not self.cached_meta_path.exists():
                return None
            compressed_size = self.cached_json_path.stat().st_size
        except OSError as error:
            raise OSError(
                f"Cannot inspect bundled snapshot {self.cached_json_path} "
                f"and {self.cached_meta_path}: {error}"
            ) from error
        data = _read_file(self.cached_meta_path, _MAX_META_BYTES)
        meta = _snapshot_meta(data, str(self.cached_meta_path))
        _check_length(compressed_size, meta.gz_size, str(self.cached_json_path))

        return meta

    def _load_initial(  # ty: ignore[missing-override-decorator]  # No override in Python 3.10.
        self,
    ) -> DataSource | None:
        if self._data is not None:
            return self._data
        meta = self._installed_meta()
        if meta is None:
            return None
        data = _read_file(self.cached_json_path, _MAX_GZIP_BYTES, expected=meta.gz_size)
        return _load_snapshot(data, meta, str(self.cached_json_path))

    def reload(  # ty: ignore[missing-override-decorator]  # No override in Python 3.10.
        self, existing_data: Optional[Data] = None
    ) -> DataSource:
        meta_data = _request(self.meta_url, _MAX_META_BYTES)
        new_meta = _snapshot_meta(meta_data, self.meta_url)
        last_modified = None if existing_data is None else existing_data.last_modified_date
        if (
            existing_data is not None
            and last_modified is not None
            and new_meta.last_modified_date <= utc_datetime(last_modified)
        ):
            return existing_data
        compressed = download(self.gz_url, new_meta.gz_size, sys.stderr.isatty())
        return _load_snapshot(compressed, new_meta, self.gz_url)


for year in range(2002, datetime.now().year + 1):
    JsonFeed(str(year))
