from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass
from datetime import datetime
from enum import IntEnum
from typing import overload, TextIO

from cvss import CVSS2, CVSS3

from cvedb.cpe import CPE, Testable


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
    url: str | None = None
    name: str | None = None


@dataclass(unsafe_hash=True, order=True, frozen=True)
class Description:
    lang: str
    value: str


class Configurations(TestableSequence, Testable):
    uid = "C"

    def __init__(self, testable: Iterable[Testable]):
        self.testable: tuple[Testable, ...] = tuple(testable)

    @overload
    def __getitem__(self, i: int) -> Testable: ...

    @overload
    def __getitem__(self, i: slice) -> TestableSequence: ...

    def __getitem__(  # ty: ignore[missing-override-decorator]  # No override in Python 3.11.
        self, i: int | slice
    ) -> Testable | TestableSequence:
        return self.testable[i]

    def __len__(  # ty: ignore[missing-override-decorator]  # No override in Python 3.11.
        self,
    ) -> int:
        return len(self.testable)

    def __eq__(  # ty: ignore[missing-override-decorator]  # No override in Python 3.11.
        self, other: object
    ) -> bool:
        return isinstance(other, Configurations) and self.testable == other.testable

    def __hash__(  # ty: ignore[missing-override-decorator]  # No override in Python 3.11.
        self,
    ) -> int:
        return hash(self.testable)

    def dump_content(  # ty: ignore[missing-override-decorator]  # No override in Python 3.11.
        self, stream: TextIO
    ) -> None:
        stream.write(str(len(self)))
        stream.write("\n")
        for child in self:
            child.dump(stream)

    @classmethod
    def load_content(  # ty: ignore[missing-override-decorator]  # No override in Python 3.11.
        cls, stream: TextIO
    ) -> "Configurations":
        num_children = int(stream.readline())
        return Configurations(Testable.load(stream) for _ in range(num_children))

    def match(  # ty: ignore[missing-override-decorator]  # No override in Python 3.11.
        self, cpe: CPE
    ) -> bool:
        """Evaluate the applicability expression for a singleton inventory."""
        return any(child.match(cpe) for child in self)

    def match_inventory(  # ty: ignore[missing-override-decorator]  # No override in Python 3.11.
        self, inventory: Iterable[CPE]
    ) -> bool:
        """Evaluate full Boolean applicability against a complete target inventory.

        Each positive criterion requires at least one matching inventory product.
        Empty configurations do not establish applicability.
        """
        inventory = tuple(inventory)
        return any(child.match_inventory(inventory) for child in self)

    def candidate_criteria(  # ty: ignore[missing-override-decorator]  # No override in Python 3.11.
        self,
    ) -> Iterator[Testable]:
        """Yield marked criteria, including those inside negated expressions."""
        for child in self:
            yield from child.candidate_criteria()

    def match_candidate(self, cpe: CPE) -> bool:
        """Find an associated vulnerable product without confirming its environment.

        Candidate searches use the vulnerable mark and preserve version ranges.
        Logical negation and required platforms are evaluated by match_inventory.
        """
        return any(criterion.match(cpe) for criterion in self.candidate_criteria())

    def __repr__(  # ty: ignore[missing-override-decorator]  # No override in Python 3.11.
        self,
    ) -> str:
        return f"{self.__class__.__name__}({self.testable!r})"

    def vulnerable_cpes(  # ty: ignore[missing-override-decorator]  # No override in Python 3.11.
        self,
    ) -> Iterator[CPE]:
        for testable in self:
            yield from testable.vulnerable_cpes()


@dataclass(unsafe_hash=True, order=True, frozen=True)
class CVE:
    cve_id: str
    published_date: datetime
    last_modified_date: datetime
    impact: CVSS3 | CVSS2 | None = None
    descriptions: tuple[Description, ...] = ()
    references: tuple[Reference, ...] = ()
    assigner: str | None = None
    configurations: Configurations = Configurations(())

    def description(self, lang: str = "en") -> str | None:
        for d in self.descriptions:
            if d.lang == lang:
                return d.value
        return None

    @property
    def severity(self) -> Severity:
        if self.impact is None or self.impact.base_score is None:
            return Severity.UNKNOWN
        score = float(self.impact.base_score)
        if isinstance(self.impact, CVSS2):
            boundaries = ((4.0, Severity.LOW), (7.0, Severity.MEDIUM))
            highest = Severity.HIGH
        else:
            if score == 0.0:
                return Severity.NONE
            boundaries = ((4.0, Severity.LOW), (7.0, Severity.MEDIUM), (9.0, Severity.HIGH))
            highest = Severity.CRITICAL
        for threshold, severity in boundaries:
            if score < threshold:
                return severity
        return highest

    def __str__(  # ty: ignore[missing-override-decorator]  # No override in Python 3.11.
        self,
    ) -> str:
        return self.cve_id
