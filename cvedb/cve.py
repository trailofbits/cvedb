from abc import abstractmethod
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from enum import IntEnum
from typing import Iterable, Iterator, Optional, overload, TextIO, Tuple, Union
import sys

from cvss import CVSS2, CVSS3

from .cpe import CPE, Testable


if sys.version_info < (3, 9):
    # collections.abc.Sequence didn't become subscriptable until Python 3.9
    TestableSequence = Sequence
else:
    TestableSequence = Sequence[Testable]


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


class Configurations(TestableSequence, Testable):
    uid = "C"

    def __init__(self, testable: Iterable[Testable]):
        self.testable: Tuple[Testable, ...] = tuple(testable)

    @overload
    @abstractmethod
    def __getitem__(self, i: int) -> Testable: ...

    @overload
    @abstractmethod
    def __getitem__(self, s: slice) -> TestableSequence: ...

    def __getitem__(self, i: int) -> Testable:
        return self.testable[i]

    def __len__(self) -> int:
        return len(self.testable)

    def __eq__(self, other):
        return isinstance(other, Configurations) and self.testable == other.testable

    def __hash__(self):
        return hash(self.testable)

    def dump_content(self, stream: TextIO):
        stream.write(str(len(self)))
        stream.write("\n")
        for child in self:
            child.dump(stream)

    @classmethod
    def load_content(cls, stream: TextIO) -> "Configurations":
        num_children = int(stream.readline())
        return Configurations(Testable.load(stream) for _ in range(num_children))

    def match(self, cpe: CPE) -> bool:
        for child in self:
            if child.match(cpe):
                return True
        return any(child.match(cpe) for child in self)

    def __repr__(self):
        return f"{self.__class__.__name__}({self.testable!r})"

    def vulnerable_cpes(self) -> Iterator[CPE]:
        for testable in self:
            yield from testable.vulnerable_cpes()


@dataclass(unsafe_hash=True, order=True, frozen=True)
class CVE:
    cve_id: str
    published_date: datetime
    last_modified_date: datetime
    impact: Optional[Union[CVSS3, CVSS2]] = None
    descriptions: Tuple[Description, ...] = ()
    references: Tuple[Reference, ...] = ()
    assigner: Optional[str] = None
    configurations: Configurations = Configurations(())

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
