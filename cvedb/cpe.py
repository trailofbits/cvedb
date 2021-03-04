from abc import ABC, ABCMeta, abstractmethod
from dataclasses import dataclass, fields
from enum import Enum
from io import StringIO
import re
from typing import Callable, Dict, Iterable, Iterator, Optional, TextIO, Tuple, Type, TypeVar, Union


AV_STRING_REGEX = re.compile(
    r"^(((\?+|\*)?([A-Za-z0-9\-._]|(\\[\\?*!\"#$%&'()+,/:;<=>@\[\]^`{|}~]))+(\?+|\*)?)|[*-]).*"
)

LANGTAG_REGEX = re.compile(r"^(([A-Za-z]{2,3})(-([A-Za-z]{2}|[0-9]{3}))?).*")


TESTABLES_BY_UID: Dict[str, Type["Testable"]] = {}


class TestableMeta(ABCMeta):
    def __init__(cls, name, bases, clsdict):
        if name == "CPE":
            clsdict["uid"] = "c"
        super().__init__(name, bases, clsdict)
        if hasattr(cls, "__abstractmethods__") and cls.__abstractmethods__:
            return
        elif clsdict.get("uid", None) is None:
            raise TypeError(f"Testable {name} must define a unique UID for serialization")
        elif clsdict["uid"] in TESTABLES_BY_UID:
            raise TypeError(f"{name}'s UID of {clsdict['uid']!r} is already registered by "
                            f"{TESTABLES_BY_UID[clsdict['uid']].__name__}")
        elif len(clsdict["uid"]) != 1:
            raise TypeError(f"{name}.uid must be exactly one character")
        TESTABLES_BY_UID[clsdict["uid"]] = cls


T = TypeVar("T", bound="Testable")


class Testable(metaclass=TestableMeta):
    uid: str

    @abstractmethod
    def match(self, cpe: "CPE") -> bool:
        raise NotImplementedError()

    @abstractmethod
    def dump_content(self, stream: TextIO):
        raise NotImplementedError()

    def dump(self, stream: TextIO):
        stream.write(self.uid)
        self.dump_content(stream)

    def dumps(self) -> str:
        ret = StringIO()
        self.dump(ret)
        return ret.getvalue()

    @staticmethod
    def load(stream: TextIO) -> "Testable":
        return TESTABLES_BY_UID[stream.read(1)].load_content(stream)

    @staticmethod
    def loads(serialized: str) -> "Testable":
        return Testable.load(StringIO(serialized))

    @classmethod
    @abstractmethod
    def load_content(cls: Type[T], stream: TextIO) -> T:
        raise NotImplementedError()

    @abstractmethod
    def vulnerable_cpes(self) -> Iterator["CPE"]:
        raise NotImplementedError()


class Part(Enum):
    HARDWARE = "h"
    OS = "o"
    APP = "a"

    def __str__(self):
        return self.value


class Logical(Enum):
    ANY = "*"
    NA = "-"

    def __str__(self):
        return self.value


class Language:
    def __init__(self, iso_639_code: str, region: Optional[Union[str, int]] = None):
        if not (2 <= len(iso_639_code) <= 3):
            raise ValueError(f"Invalid ISO 639 language code: {iso_639_code!r}")
        elif region == "":
            region = None
        elif isinstance(region, str):
            if len(region) != 2:
                if len(region) == 3:
                    # see if it is actually a three digit UN M.49 code:
                    try:
                        region = int(region)
                    except ValueError:
                        pass
                if isinstance(region, str):
                    raise ValueError(f"Invalid ISO 3166-1 region code: {region!r}")
            elif not re.match(r"[A-Za-z]{2}", region):
                raise ValueError(f"Invalid ISO 3166-1 region code: {region!r}")
            else:
                region = region.lower()
        elif isinstance(region, int) and (region < 0 or region > 999):
            raise ValueError(f"Invalid UN M.49 region code: {region!r}")
        self.code: str = iso_639_code.lower()
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
        elif isinstance(self.region, int):
            return f"{self.code}-{self.region:03}"
        else:
            return f"{self.code}-{self.region}"

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

    def is_complete_wildcard(self) -> bool:
        for field in fields(self.__class__):
            if getattr(self, field.name) != Logical.ANY:
                return False
        return True

    @property
    def uid(self) -> str:
        return "c"

    @staticmethod
    def _match(a, b) -> bool:
        if isinstance(a, Logical):
            if a == Logical.ANY:
                return True
            else:
                return b == Logical.NA
        elif isinstance(b, Logical):
            if b == Logical.ANY:
                return True
            else:
                return a == Logical.NA
        return a == b

    def match(self, cpe: "CPE", match_version: bool = True) -> bool:
        return all(CPE._match(getattr(self, attr), getattr(cpe, attr)) for attr in (
            "part", "vendor", "product", "update", "edition", "lang", "sw_edition", "target_sw",
            "target_hw", "other"
        )) and (not match_version or CPE._match(self.version, cpe.version))

    def formatted_string(self) -> str:
        return "cpe:2.3:" + ":".join(str(getattr(self, attr)) for attr in (
            "part", "vendor", "product", "version", "update", "edition", "lang", "sw_edition", "target_sw",
            "target_hw", "other"
        ))

    __str__ = formatted_string

    def dump_content(self, stream: TextIO):
        stream.write(self.formatted_string())
        stream.write("\n")

    @classmethod
    def load_content(cls: Type[T], stream: TextIO) -> T:
        return parse_formatted_string(stream.readline())

    def vulnerable_cpes(self) -> Iterator["CPE"]:
        yield self


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


class LogicalTest(Testable, ABC):
    def __init__(self, children: Iterable[Union["LogicalTest", CPE]], negate: bool = False):
        self.children: Tuple[Union[LogicalTest, CPE], ...] = tuple(children)
        self.negate: bool = negate

    def __eq__(self, other):
        return isinstance(other, LogicalTest) and other.uid == self.uid and other.negate == self.negate and \
               other.children == self.children

    def __hash__(self):
        return hash((self.negate,) + self.children)

    @classmethod
    def load_content(cls: Type[T], stream: TextIO) -> T:
        negate = stream.read(1) == "~"
        num_children = int(stream.readline())
        children = [Testable.load(stream) for i in range(num_children)]
        return cls(children, negate)

    def dump_content(self, stream: TextIO):
        if self.negate:
            stream.write("~")
        else:
            stream.write("=")
        stream.write(f"{len(self.children)!s}\n")
        for child in self.children:
            child.dump(stream)

    def vulnerable_cpes(self) -> Iterator[CPE]:
        if not self.negate:
            for c in self.children:
                yield from c.vulnerable_cpes()
        else:
            return iter(())


class And(LogicalTest):
    uid = "a"

    def match(self, cpe: CPE) -> bool:
        result = all(child.match(cpe) for child in self.children)
        if self.negate:
            return not result
        else:
            return result


class Or(LogicalTest):
    uid = "o"

    def match(self, cpe: CPE) -> bool:
        result = any(child.match(cpe) for child in self.children)
        if self.negate:
            return not result
        else:
            return result


class Negate(Testable):
    uid = "!"

    def __init__(self, wrapped: Testable):
        self.wrapped: Testable = wrapped

    def __eq__(self, other):
        return isinstance(other, Negate) and self.wrapped == other.wrapped

    def __hash__(self):
        return hash(self.wrapped)

    def match(self, cpe: "CPE") -> bool:
        return not self.wrapped.match(cpe)

    def dump_content(self, stream: TextIO):
        self.wrapped.dump(stream)

    @classmethod
    def load_content(cls: Type[T], stream: TextIO) -> T:
        return cls(Testable.load(stream))

    def vulnerable_cpes(self) -> Iterator[CPE]:
        return iter(())


class VersionRange(Testable):
    uid = "v"

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

    def __eq__(self, other):
        return isinstance(other, VersionRange) and self.start == other.start and self.end == other.end and \
               self.include_start == other.include_start and self.include_end == other.include_end and \
               self.wrapped == other.wrapped

    def __hash__(self):
        return hash((self.wrapped, self.start, self.end, self.include_start, self.include_end))

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

    def dump_content(self, stream: TextIO):
        stream.write(["E", "I"][self.include_start])
        if self.start is not None:
            stream.write(str(self.start))
        stream.write("\n")
        stream.write(["E", "I"][self.include_end])
        if self.end is not None:
            stream.write(str(self.end))
        stream.write("\n")
        self.wrapped.dump(stream)

    @classmethod
    def load_content(cls: Type[T], stream: TextIO) -> T:
        include_start = stream.read(1) == "I"
        start = stream.readline()
        if not start:
            start = None
        include_end = stream.read(1) == "I"
        end = stream.readline()
        if not end:
            end = None
        return cls(Testable.load(stream), start=start, end=end, include_start=include_start, include_end=include_end)

    def vulnerable_cpes(self) -> Iterator[CPE]:
        yield from self.wrapped.vulnerable_cpes()
