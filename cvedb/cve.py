from dataclasses import dataclass
from datetime import datetime
from enum import IntEnum
from typing import Optional, Tuple, Union

from cvss import CVSS2, CVSS3


class Severity(IntEnum):
    NONE = 0
    UNKNOWN = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5


@dataclass(unsafe_hash=True, order=True, frozen=True)
class Reference:
    url: Optional[str] = None
    name: Optional[str] = None


@dataclass(unsafe_hash=True, order=True, frozen=True)
class Description:
    lang: str
    value: str


@dataclass(unsafe_hash=True, order=True, frozen=True)
class CVE:
    cve_id: str
    published_date: datetime
    last_modified_date: datetime
    impact: Optional[Union[CVSS3, CVSS2]] = None
    descriptions: Tuple[Description, ...] = ()
    references: Tuple[Reference, ...] = ()
    assigner: Optional[str] = None

    def description(self, lang: str = "en") -> Optional[str]:
        for d in self.descriptions:
            if d.lang == lang:
                return d.value
        return None

    @property
    def severity(self) -> Severity:
        if isinstance(self.impact, CVSS2):
            if self.impact.base_score < 4.0:
                return Severity.LOW
            elif self.impact.base_score < 7.0:
                return Severity.MEDIUM
            else:
                return Severity.HIGH
        elif isinstance(self.impact, CVSS3):
            if self.impact.base_score == 0.0:
                return Severity.NONE
            elif self.impact.base_score < 4.0:
                return Severity.LOW
            elif self.impact.base_score < 7.0:
                return Severity.MEDIUM
            elif self.impact.base_score < 9.0:
                return Severity.HIGH
            else:
                return Severity.CRITICAL
        else:
            return Severity.UNKNOWN

    def __str__(self):
        return self.cve_id
