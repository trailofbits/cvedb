from abc import ABC, abstractmethod
from datetime import datetime, timezone
from dataclasses import replace
from enum import Enum
from typing import Any, Optional, Tuple
from collections.abc import Iterable

from cvedb.cpe import CPE
from cvedb.cve import CVE


class Sort(Enum):
    CVE_ID = 0
    DESCRIPTION = 1
    PUBLISHED_DATE = 2
    LAST_MODIFIED_DATE = 3
    IMPACT = 4
    SEVERITY = 5

    def get_key(self, cve: CVE) -> Any:
        if self == Sort.IMPACT:
            if cve.impact is None or cve.impact.base_score is None:
                return float("-inf")
            return float(cve.impact.base_score)
        if self == Sort.DESCRIPTION:
            fallback = cve.descriptions[0].value if cve.descriptions else ""
            return cve.description() or fallback
        return getattr(cve, self.name.lower())


class SearchQuery(ABC):
    @abstractmethod
    def matches(self, cve: CVE) -> bool:
        return False


def _utc_datetime(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


class AbstractDateQuery(SearchQuery, ABC):
    def __init__(self, date: datetime):
        self.date: datetime = _utc_datetime(date)

    @abstractmethod
    def get_field(self, cve: CVE) -> datetime:
        raise NotImplementedError()


class BeforeQuery(AbstractDateQuery, ABC):
    def __init__(self, date_before: datetime):
        super().__init__(date_before)

    def matches(  # ty: ignore[missing-override-decorator]  # No override in Python 3.10.
        self, cve: CVE
    ) -> bool:
        return _utc_datetime(self.get_field(cve)) <= self.date


class AfterQuery(AbstractDateQuery, ABC):
    def __init__(self, date_after: datetime):
        super().__init__(date_after)

    def matches(  # ty: ignore[missing-override-decorator]  # No override in Python 3.10.
        self, cve: CVE
    ) -> bool:
        return _utc_datetime(self.get_field(cve)) >= self.date


class AfterPublishedDateQuery(AfterQuery):
    def __init__(self, date_after: datetime):
        super().__init__(date_after)

    def get_field(  # ty: ignore[missing-override-decorator]  # No override in Python 3.10.
        self, cve: CVE
    ) -> datetime:
        return cve.published_date


class BeforePublishedDateQuery(BeforeQuery):
    def __init__(self, date_before: datetime):
        super().__init__(date_before)

    def get_field(  # ty: ignore[missing-override-decorator]  # No override in Python 3.10.
        self, cve: CVE
    ) -> datetime:
        return cve.published_date


class AfterModifiedDateQuery(AfterQuery):
    def __init__(self, date_after: datetime):
        super().__init__(date_after)

    def get_field(  # ty: ignore[missing-override-decorator]  # No override in Python 3.10.
        self, cve: CVE
    ) -> datetime:
        return cve.last_modified_date


class BeforeModifiedDateQuery(BeforeQuery):
    def __init__(self, date_before: datetime):
        super().__init__(date_before)

    def get_field(  # ty: ignore[missing-override-decorator]  # No override in Python 3.10.
        self, cve: CVE
    ) -> datetime:
        return cve.last_modified_date


class TermQuery(SearchQuery):
    def __init__(self, query: str, case_sensitive: bool = False):
        self._query: str = query
        self.case_sensitive: bool = case_sensitive

    @property
    def query(self) -> str:
        return self._query

    def _contains(self, value: str | None) -> bool:
        if value is None:
            return False
        if self.case_sensitive:
            return self._query in value
        return self._query.lower() in value.lower()

    def matches(  # ty: ignore[missing-override-decorator]  # No override in Python 3.10.
        self, cve: CVE
    ) -> bool:
        if self._contains(cve.cve_id) or self._contains(cve.assigner):
            return True
        if any(self._contains(description.value) for description in cve.descriptions):
            return True
        return any(self._contains(ref.name) or self._contains(ref.url) for ref in cve.references)

    @property
    def _normalized_query(self) -> str:
        if self.case_sensitive:
            return self._query
        else:
            return self._query.lower()

    def __hash__(  # ty: ignore[missing-override-decorator]  # No override in Python 3.10.
        self,
    ) -> int:
        return hash(self._normalized_query)

    def __eq__(  # ty: ignore[missing-override-decorator]  # No override in Python 3.10.
        self, other: object
    ) -> bool:
        return (
            isinstance(other, TermQuery)
            and other._normalized_query == self._normalized_query
            and self.case_sensitive == other.case_sensitive
        )

    def __lt__(self, other: object) -> bool:
        return isinstance(other, TermQuery) and self._normalized_query < other._normalized_query

    def __str__(  # ty: ignore[missing-override-decorator]  # No override in Python 3.10.
        self,
    ) -> str:
        return self._query

    def __repr__(  # ty: ignore[missing-override-decorator]  # No override in Python 3.10.
        self,
    ) -> str:
        return (
            f"{self.__class__.__name__}(query={self._query!r}, "
            f"case_sensitive={self.case_sensitive!r})"
        )


class DescriptionQuery(TermQuery):
    def matches(  # ty: ignore[missing-override-decorator]  # No override in Python 3.10.
        self, cve: CVE
    ) -> bool:
        for description in cve.descriptions:
            if (self.case_sensitive and self._query in description.value) or (
                not self.case_sensitive and self._query.lower() in description.value.lower()
            ):
                return True
        return False


class CompoundQuery(SearchQuery, ABC):
    def __init__(self, *sub_queries: SearchQuery):
        self.sub_queries: Tuple[SearchQuery, ...] = tuple(sub_queries)


class AndQuery(CompoundQuery):
    def matches(  # ty: ignore[missing-override-decorator]  # No override in Python 3.10.
        self, cve: CVE
    ) -> bool:
        return all(q.matches(cve) for q in self.sub_queries)


class OrQuery(CompoundQuery):
    def matches(  # ty: ignore[missing-override-decorator]  # No override in Python 3.10.
        self, cve: CVE
    ) -> bool:
        return any(q.matches(cve) for q in self.sub_queries)


class CPEQuery(SearchQuery):
    """Find candidate associations with vulnerable-marked product criteria.

    Required platforms and logical negation do not confirm applicability in a
    candidate search. Use EnvironmentQuery for complete inventory evaluation.
    """

    def __init__(self, cpe: Optional[CPE] = None, **kwargs: object) -> None:
        if cpe is None:
            self.cpe: CPE = replace(CPE(), **kwargs)
        else:
            self.cpe = cpe

    def matches(  # ty: ignore[missing-override-decorator]  # No override in Python 3.10.
        self, cve: CVE
    ) -> bool:
        return cve.configurations.match_candidate(self.cpe)


class EnvironmentQuery(SearchQuery):
    """Confirm applicability against a complete inventory, including required platforms."""

    def __init__(self, inventory: Iterable[CPE]) -> None:
        self.inventory = tuple(inventory)

    def matches(  # ty: ignore[missing-override-decorator]  # No override in Python 3.10.
        self, cve: CVE
    ) -> bool:
        return cve.configurations.match_inventory(self.inventory)
