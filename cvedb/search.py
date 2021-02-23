from abc import ABC, abstractmethod
from typing import Tuple

from .cve import CVE


class SearchQuery(ABC):
    @abstractmethod
    def matches(self, cve: CVE) -> bool:
        return False


class TermQuery(SearchQuery):
    def __init__(self, query: str, case_sensitive: bool = False):
        self._query: str = query
        self.case_sensitive: bool = case_sensitive

    @property
    def query(self) -> str:
        return self._query

    def matches(self, cve: CVE) -> bool:
        for description in cve.descriptions:
            if (self.case_sensitive and self._query in description.value) or \
                    (not self.case_sensitive and self._query.lower() in description.value.lower()):
                return True
        if self._query in cve.cve_id:
            return True
        for reference in cve.references:
            if (self.case_sensitive and self._query in reference.name) or \
                    (not self.case_sensitive and self._query.lower() in reference.name.lower()):
                return True
            elif (self.case_sensitive and self._query in reference.url) or \
                    (not self.case_sensitive and self._query.lower() in reference.url.lower()):
                return True
        if cve.assigner is not None and self._query in cve.assigner:
            return True
        return False

    @property
    def _normalized_query(self) -> str:
        if self.case_sensitive:
            return self._query
        else:
            return self._query.lower()

    def __hash__(self):
        return hash(self._normalized_query)

    def __eq__(self, other):
        return isinstance(other, SearchQuery) and other._normalized_query == self._normalized_query and \
               self.case_sensitive == other.case_sensitive

    def __lt__(self, other):
        return isinstance(other, SearchQuery) and self._normalized_query < other._normalized_query

    def __str__(self):
        return self._query

    def __repr__(self):
        return f"{self.__class__.__name__}(query={self._query!r}, case_sensitive={self.case_sensitive!r})"


class DescriptionQuery(TermQuery):
    def matches(self, cve: CVE) -> bool:
        for description in cve.descriptions:
            if (self.case_sensitive and self._query in description.value) or \
                    (not self.case_sensitive and self._query.lower() in description.value.lower()):
                return True
        return False


class CompoundQuery(SearchQuery, ABC):
    def __init__(self, *sub_queries: SearchQuery):
        self.sub_queries: Tuple[SearchQuery, ...] = tuple(sub_queries)


class AndQuery(CompoundQuery):
    def matches(self, cve: CVE) -> bool:
        return all(q.matches(cve) for q in self.sub_queries)


class OrQuery(CompoundQuery):
    def matches(self, cve: CVE) -> bool:
        return any(q.matches(cve) for q in self.sub_queries)
