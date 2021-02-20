from dataclasses import dataclass
from datetime import datetime
import sys
from typing import Iterable, Optional, TextIO, Union
import urllib.request

from tqdm import tqdm

from .cve import CVE
from .feed import Data, Feed

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
    def loads(meta_str: Union[str, bytes]):
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
                value = datetime.fromisoformat(value)
            elif key == "sha256":
                value = bytes.fromhex(value)
            else:
                value = int(value)
            kvs[key] = value
        return Meta(**kvs)

    @staticmethod
    def load(stream: TextIO):
        return Meta.loads(stream.read())


class JsonData(Data):
    def __init__(self, cves: Iterable[CVE], meta: Meta):
        super().__init__(cves, meta.last_modified_date)
        self.meta: Meta = meta


def download(url: str, size: Optional[int] = None, show_progress: bool = True) -> bytes:
    with urllib.request.urlopen(url) as req:
        if not show_progress:
            return req.read()
        ret = bytearray()
        filename = url[url.find("/")+1:]
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
    def __init__(self, name: str, initial_data: Optional[JsonData] = None):
        super().__init__(name, initial_data)
        self.meta_url: str = f"{BASE_JSON_URL}{self.name}.meta"
        self.gz_url: str = f"{BASE_JSON_URL}{self.name}.json.gz"

    def reload(self, existing_data: Optional[Data] = None) -> Data:
        with urllib.request.urlopen(self.meta_url) as req:
            new_meta = Meta.load(req)
        if existing_data is not None and new_meta.last_modified_date <= existing_data.last_modified_date:
            # the existing data is newer
            return existing_data
        data = download(self.gz_url, new_meta.gz_size, sys.stderr.isatty())
        return JsonData((), new_meta)
