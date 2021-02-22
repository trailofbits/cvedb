from abc import ABC, abstractmethod
from collections.abc import Hashable, Iterable as IterableABC, Sized
from datetime import datetime
import time
from typing import Dict, FrozenSet, Iterable, Iterator, Optional

from .cve import CVE

MAX_DATA_AGE_SECONDS: int = 14400  # 4 hours


class DataSource(ABC, Hashable, IterableABC[CVE]):
    def __init__(self, last_modified_date: datetime):
        self.last_modified_date: datetime = last_modified_date

    def __eq__(self, other):
        return isinstance(other, DataSource) and self.last_modified_date == other.last_modified_date

    def __lt__(self, other):
        return self.last_modified_date < other.last_modified_date

    def __hash__(self):
        return hash(self.last_modified_date)


class Data(DataSource, Sized, ABC):
    pass


class InMemoryData(Data):
    def __init__(self, last_modified_date: datetime, cves: Iterable[CVE]):
        super().__init__(last_modified_date)
        self.cves: FrozenSet[CVE] = frozenset(cves)

    @staticmethod
    def load(source: DataSource) -> "Data":
        return InMemoryData(source.last_modified_date, source)

    def __iter__(self) -> Iterator[CVE]:
        return iter(self.cves)

    def __len__(self):
        return len(self.cves)


FEEDS: Dict[str, "Feed"] = {}


class Feed(ABC):
    register: bool = True

    def __init__(self, name: str, initial_data: Optional[Data] = None):
        self.name: str = name
        self._data: Optional[Data] = initial_data
        if self.register:
            if self.name in FEEDS:
                raise ValueError(f"A feed named {self.name} is already registered!")
            FEEDS[self.name] = self

    def last_modified(self) -> Optional[datetime]:
        if self._data is not None:
            return self._data.last_modified_date
        else:
            return None

    def data(self, force_reload: bool = False) -> Data:
        last_modified = self.last_modified()
        if last_modified is None or force_reload or \
                int(time.time()) - last_modified.timestamp() >= MAX_DATA_AGE_SECONDS:
            self._data = InMemoryData.load(self.reload(self._data))
        return self._data

    @abstractmethod
    def reload(self, existing_data: Optional[Data] = None) -> DataSource:
        pass
