"""Local feed and transport fixtures for snapshot behavior tests."""

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from gzip import compress
from hashlib import sha256
from io import BytesIO
import json
from pathlib import Path
from urllib.request import Request

from cvedb.nvd import JsonFeed, Meta

NOW = datetime(2020, 1, 2, tzinfo=timezone.utc)


@dataclass(frozen=True)
class Snapshot:
    raw: bytes
    compressed: bytes
    meta: Meta

    def metadata(self) -> bytes:
        return (
            f"lastModifiedDate:{self.meta.last_modified_date.isoformat()}\n"
            f"size:{self.meta.size}\nzipSize:{self.meta.zip_size}\ngzSize:{self.meta.gz_size}\n"
            f"sha256:{self.meta.sha256.hex()}\n"
        ).encode()


def snapshot(text: str = "alpha", *, raw: bytes | None = None) -> Snapshot:
    if raw is None:
        raw = json.dumps(
            {
                "CVE_Items": [
                    {
                        "cve": {
                            "CVE_data_meta": {"ID": "CVE-2020-0001"},
                            "description": {"description_data": [{"lang": "en", "value": text}]},
                        },
                        "publishedDate": NOW.isoformat(),
                        "lastModifiedDate": NOW.isoformat(),
                        "impact": {},
                    }
                ],
            }
        ).encode()
    compressed = compress(raw, mtime=0)
    return Snapshot(raw, compressed, Meta(NOW, len(raw), 0, len(compressed), sha256(raw).digest()))


class Response:
    def __init__(
        self, data: bytes, *, chunk_size: int = 65536, after_read: Callable[[], None] | None = None
    ) -> None:
        self.stream = BytesIO(data)
        self.headers = {"Content-Length": str(len(data))}
        self.chunk_size = chunk_size
        self.after_read = after_read
        self.read_sizes: list[int] = []

    def __enter__(self) -> "Response":
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.stream.close()

    def read(self, size: int = -1) -> bytes:
        self.read_sizes.append(size)
        return self.stream.read(size)

    def read1(self, size: int = -1) -> bytes:
        self.read_sizes.append(size)
        if size < 0:
            raise AssertionError("Unbounded transport read")
        result = self.stream.read(min(size, self.chunk_size))
        if self.after_read is not None:
            self.after_read()
        return result


class LocalJsonFeed(JsonFeed):
    register = False


def local_feed(path: Path, value: Snapshot, *, name: str = "fixture") -> LocalJsonFeed:
    feed = LocalJsonFeed(name)
    feed.cached_json_path = path / f"{name}.json.gz"
    feed.cached_meta_path = path / f"{name}.meta"
    feed.cached_json_path.write_bytes(value.compressed)
    feed.cached_meta_path.write_bytes(value.metadata())
    return feed


def route(value: Snapshot) -> Callable[..., Response]:
    def open_response(request: Request | str, *, timeout: float | None = None) -> Response:
        url = request.full_url if isinstance(request, Request) else request
        return Response(value.metadata() if url.endswith(".meta") else value.compressed)

    return open_response
