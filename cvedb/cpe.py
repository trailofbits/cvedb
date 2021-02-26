from abc import ABC
from dataclasses import dataclass
from enum import Enum
import re
from typing import Callable, Iterable, Iterator, Optional, Tuple, Union
import sys

if sys.version_info < (3, 8):
    from typing_extensions import Protocol, runtime_checkable
else:
    from typing import Protocol, runtime_checkable


AV_STRING_REGEX = re.compile(
    r"^(((\?+|\*)?([A-Za-z0-9\-._]|(\\[\\?*!\"#$%&'()+,/:;<=>@\[\]^`{|}~]))+(\?+|\*)?)|[*-]).*"
)

LANGTAG_REGEX = re.compile(r"^(([A-Za-z]{2,3})(-([A-Za-z]{2}|[0-9]{3}))?).*")


@runtime_checkable
class Testable(Protocol):
    def match(self, cpe: "CPE") -> bool:
        ...


class Part(Enum):
    HARDWARE = "h"
    OS = "o"
    APP = "a"


class Logical(Enum):
    ANY = "*"
    NA = "-"


class Language:
    def __init__(self, iso_639_code: str, region: Optional[Union[str, int]] = None):
        if not (2 <= len(iso_639_code) <= 3):
            raise ValueError(f"Invalid ISO 639 language code: {iso_639_code!r}")
        elif region == "":
            region = None
        elif isinstance(region, str) and len(region) != 2:
            if len(region) == 3:
                # see if it is actually a three digit UN M.49 code:
                try:
                    region = int(region)
                except ValueError:
                    pass
            if isinstance(region, str):
                raise ValueError(f"Invalid ISO 3166-1 region code: {region!r}")
        elif isinstance(region, int) and (region < 0 or region > 999):
            raise ValueError(f"Invalid UN M.49 region code: {region!r}")
        self.code: str = iso_639_code
        self.region: Optional[Union[str, int]] = region

    def __eq__(self, other):
        return (isinstance(other, Language) and other.code == self.code and other.region == self.region) or (
                    isinstance(other, str) and (
                        (self.region is None and self.code == other) or
                        (self.region is not None and str(self) == other)
                    )
        )

    def __hash__(self):
        if self.region is None:
            return hash((self.code, ""))
        else:
            return hash((self.code, str(self.region)))

    def __lt__(self, other):
        return str(self) < str(other)

    def __str__(self):
        if self.region is None:
            return self.code
        else:
            return f"{self.code}-{self.region!s}"

    def __repr__(self):
        return f"{self.__class__.__name__}(iso_639_code={self.code!r}, region={self.region!r})"


AVString = Union[str, Logical]


@dataclass(unsafe_hash=True, frozen=True, order=True)
class CPE(Testable):
    part: Union[Part, Logical] = Logical.ANY
    vendor: AVString = Logical.ANY
    product: AVString = Logical.ANY
    version: AVString = Logical.ANY
    update: AVString = Logical.ANY
    edition: AVString = Logical.ANY
    lang: Union[Language, Logical] = Logical.ANY
    sw_edition: AVString = Logical.ANY
    target_sw: AVString = Logical.ANY
    target_hw: AVString = Logical.ANY
    other: AVString = Logical.ANY

    @staticmethod
    def _match(a, b) -> bool:
        if isinstance(a, Logical):
            if a == Logical.ANY:
                return True
            else:
                return b == Logical.NA
        return a == b

    def match(self, cpe: "CPE", match_version: bool = True) -> bool:
        return all(CPE._match(getattr(self, attr), getattr(cpe, attr)) for attr in (
            "part", "vendor", "product", "update", "edition", "lang", "sw_edition", "target_sw",
            "target_hw", "other"
        )) and (not match_version or CPE._match(self.version, cpe.version))


class FormattedStringError(ValueError):
    pass


class ParseContext:
    def __init__(self, parser: "FormattedStringParser"):
        self.parser: FormattedStringParser = parser
        self._start_offset: int = self.parser.offset

    def __enter__(self) -> "FormattedStringParser":
        self._start_offset = self.parser.offset
        return self.parser

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is not None or exc_val is not None or exc_tb is not None:
            self.parser.offset = self._start_offset


class FormattedStringParser:
    def __init__(self, fs: str):
        self.fs: str = fs
        self.offset: int = 0

    def context(self) -> ParseContext:
        return ParseContext(self)

    def error(self, expected: str):
        if self.offset >= len(self.fs):
            raise FormattedStringError(f"Reached the end of the formatted string while searching for {expected!r}")
        raise FormattedStringError(f"Expected {expected!r} but instead found "
                                   f"{self.fs[self.offset:self.offset+len(expected)]!r}\n{self.fs}\n"
                                   f"{' ' * self.offset}{'^' * len(expected)}\n")

    def expect(self, text: str):
        if self.offset >= len(self.fs) or self.fs[self.offset:self.offset + len(text)] != text:
            if not text:
                return ""
            self.error(text)
        self.offset += len(text)

    def up_to(self, delimiter: str, consume_delimiter: bool = True) -> str:
        i = self.fs[self.offset:].find(delimiter)
        if i < 0:
            raise FormattedStringError(f"Reached the end of the formatted string when searching for {delimiter} from "
                                       f"offset {self.offset}")
        ret = self.fs[self.offset:self.offset + i]
        self.offset += i
        if consume_delimiter:
            self.offset += len(delimiter)
        return ret

    def peek(self) -> str:
        return self.fs[self.offset:self.offset + 1]

    def parse_repeated(
            self, parser: Callable[[], str], at_least: int = 0, at_most: Optional[int] = None
    ) -> Iterator[str]:
        if at_most is not None and at_most < at_least:
            return
        yielded = 0
        error = None
        while yielded < at_least and (at_most is None or yielded < at_most):
            try:
                with self.context():
                    yield parser()
                yielded += 1
            except FormattedStringError as e:
                error = e
                break
        if yielded < at_least:
            assert error is not None
            raise error

    def parse_avstring(self) -> Union[str, Logical]:
        m = AV_STRING_REGEX.match(self.fs[self.offset:])
        if m:
            match = m.group(1)
            self.offset += len(match)
            if match == "*":
                return Logical.ANY
            elif match == "-":
                return Logical.NA
            else:
                return match
        next_colon = self.offset + self.fs[self.offset:].find(":")
        raise FormattedStringError(f"Invalid string {self.fs[self.offset:next_colon]!r}\n{self.fs}\n"
                                   f"{' ' * self.offset}{'^' * (next_colon - self.offset)}")

    def parse_langtag(self) -> Language:
        m = LANGTAG_REGEX.match(self.fs[self.offset:])
        if m:
            self.offset += len(m.group(1))
            return Language(iso_639_code=m.group(2), region=m.group(4))
        next_colon = self.offset + self.fs[self.offset:].find(":")
        raise FormattedStringError(f"Invalid language tag {self.fs[self.offset:next_colon]!r}\n{self.fs}\n"
                                   f"{' ' * self.offset}{'^' * (next_colon - self.offset)}")

    def parse_lang(self) -> Union[Language, Logical]:
        next_char = self.peek()
        if next_char == "*":
            self.offset += 1
            return Logical.ANY
        elif next_char == "-":
            self.offset += 1
            return Logical.NA
        return self.parse_langtag()

    def parse(self) -> CPE:
        self.offset = 0
        self.expect("cpe:")
        version = self.up_to(":")
        if version != "2.3":
            raise FormattedStringError(f"Invalid version CPE version \"{version}\"; only 2.3 is currently supported")
        part_char = self.up_to(":")
        for part_possibility in Part:
            if part_possibility.value == part_char:
                part = part_possibility
                break
        else:
            if part_char == "*":
                part = Logical.ANY
            elif part_char == "-":
                part = Logical.NA
            else:
                raise FormattedStringError(f"Invalid CPE part specifier: {part_char!r}")
        vendor = self.parse_avstring()
        self.expect(":")
        product = self.parse_avstring()
        self.expect(":")
        version = self.parse_avstring()
        self.expect(":")
        update = self.parse_avstring()
        self.expect(":")
        edition = self.parse_avstring()
        self.expect(":")
        lang = self.parse_lang()
        self.expect(":")
        sw_edition = self.parse_avstring()
        self.expect(":")
        target_sw = self.parse_avstring()
        self.expect(":")
        target_hw = self.parse_avstring()
        self.expect(":")
        other = self.parse_avstring()
        return CPE(
            part=part,
            vendor=vendor,
            product=product,
            version=version,
            update=update,
            edition=edition,
            lang=lang,
            sw_edition=sw_edition,
            target_sw=target_sw,
            target_hw=target_hw,
            other=other
        )


def parse_formatted_string(fs: str) -> CPE:
    return FormattedStringParser(fs).parse()


class TestError(ValueError):
    pass


class LogicalTest(ABC, Testable):
    def __init__(self, children: Iterable[Union["LogicalTest", CPE]], negate: bool = False):
        self.children: Tuple[Union[LogicalTest, CPE], ...] = tuple(children)
        self.negate: bool = negate


class And(LogicalTest):
    def match(self, cpe: CPE) -> bool:
        result = all(cpe.match(child) for child in self.children)
        if self.negate:
            return not result
        else:
            return result


class Or(LogicalTest):
    def match(self, cpe: CPE) -> bool:
        result = any(cpe.match(child) for child in self.children)
        if self.negate:
            return not result
        else:
            return result


class Negate(Testable):
    def __init__(self, wrapped: Testable):
        self.wrapped: Testable = wrapped

    def match(self, cpe: "CPE") -> bool:
        return not self.wrapped.match(cpe)


class VersionRange(Testable):
    def __init__(
            self,
            wrapped: CPE,
            start: Optional[str] = None,
            end: Optional[str] = None,
            include_start: bool = True,
            include_end: bool = True
    ):
        self.wrapped: CPE = wrapped
        self.start: Optional[str] = start
        self.end: Optional[str] = end
        self.include_start: bool = include_start
        self.include_end: bool = include_end

    def match(self, cpe: "CPE") -> bool:
        if isinstance(cpe.version, str):
            if self.start is not None:
                if self.include_start:
                    if cpe.version < self.start:
                        return False
                elif cpe.version <= self.start:
                    return False
            elif self.end is not None:
                if self.include_end:
                    if cpe.version > self.end:
                        return False
                elif cpe.version >= self.end:
                    return False
        return self.wrapped.match(cpe, match_version=False)
