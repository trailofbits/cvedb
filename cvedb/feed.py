from abc import ABC, abstractmethod
import datetime
import time
from typing import Iterable, List, Optional

from .cve import CVE

MAX_DATA_AGE_SECONDS: int = 14400  # 4 hours


class Data:
    def __init__(self, cves: Iterable[CVE], last_modified_date: datetime):
        self.cves: List[CVE] = list(cves)
        self.last_modified_date: datetime = last_modified_date

    def __eq__(self, other):
        return isinstance(other, Data) and self.last_modified_date == other.last_modified_date

    def __lt__(self, other):
        return self.last_modified_date < other.last_modified_date

    def __hash__(self):
        return hash(self.last_modified_date)


class Feed(ABC):
    def __init__(self, name: str, initial_data: Optional[Data] = None):
        self.name: str = name
        self._data: Optional[Data] = initial_data

    def data(self, force_reload: bool = False) -> Data:
        if self._data is None or force_reload or \
                int(time.time()) - self._data.last_modified_date.timestamp() >= MAX_DATA_AGE_SECONDS:
            self._data = self.reload(self._data)
        return self._data

    @abstractmethod
    def reload(self, existing_data: Optional[Data] = None) -> Data:
        pass
