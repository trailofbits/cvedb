from abc import ABC, abstractmethod
from collections.abc import Hashable, Iterable as IterableABC, Sized
from datetime import datetime
from sys import version_info
import time
from typing import Any, Callable, Dict, FrozenSet, Iterable, Iterator, Optional, Tuple, Union

from .cve import CVE
from .search import OrQuery, SearchQuery, Sort, TermQuery

MAX_DATA_AGE_SECONDS: int = 86400  # 1 day


if version_info < (3, 9):
    # collections.abc.Iterable didn't become subscriptable until Python 3.9
    IterableCVE = IterableABC
else:
    IterableCVE = IterableABC[CVE]


class DataSource(ABC, Hashable, IterableCVE):
    def __init__(self, last_modified_date: datetime):
        self.last_modified_date: datetime = last_modified_date

    def __eq__(self, other):
        return isinstance(other, DataSource) and self.last_modified_date == other.last_modified_date

    def __lt__(self, other):
        return self.last_modified_date < other.last_modified_date

    def __hash__(self):
        return hash(self.last_modified_date)


class Data(DataSource, Sized, ABC):
    @staticmethod
    def make_query(*queries: Union[str, SearchQuery]) -> SearchQuery:
        sq = []
        for query in queries:
            if isinstance(query, SearchQuery):
                sq.append(query)
            else:
                sq.append(TermQuery(str(query)))
        if len(sq) == 1:
            return sq[0]
        else:
            return OrQuery(*sq)

    @staticmethod
    def sort_key(*sorts: Sort) -> Callable[[CVE], Tuple[Any, ...]]:
        def get_key(cve: CVE):
            return tuple(sort.get_key(cve) for sort in sorts)

        return get_key

    def search(
            self,
            *queries: Union[str, SearchQuery],
            sort: Iterable[Sort] = (Sort.CVE_ID,),
            ascending: bool = True
    ) -> Iterator[CVE]:
        query = Data.make_query(*queries)
        for cve in sorted(self, key=Data.sort_key(*sort), reverse=not ascending):
            if query.matches(cve):
                yield cve


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

    def is_out_of_date(self) -> bool:
        last_modified = self.last_modified()
        return last_modified is None or int(time.time()) - last_modified.timestamp() >= MAX_DATA_AGE_SECONDS

    def data(self, force_reload: bool = False) -> Data:
        if force_reload or self.is_out_of_date():
            self._data = InMemoryData.load(self.reload(self._data))
        return self._data

    @abstractmethod
    def reload(self, existing_data: Optional[Data] = None) -> DataSource:
        pass
