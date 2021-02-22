from dataclasses import dataclass
from datetime import datetime
from typing import Optional, Tuple, Union

from cvss import CVSS2, CVSS3


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

    def __str__(self):
        return self.cve_id
