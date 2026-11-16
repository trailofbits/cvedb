from abc import ABC, ABCMeta, abstractmethod
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, fields
from enum import Enum
from io import StringIO
import re
from typing import ClassVar, NoReturn, TextIO, cast


AV_STRING_REGEX = re.compile(
    r"^(((\?+|\*)?([A-Za-z0-9\-._]|(\\[\\?*!\"#$%&'()+,/:;<=>@\[\]^`{|}~]))+(\?+|\*)?)|[*-]).*"
)
LANGTAG_REGEX = re.compile(r"^(([A-Za-z]{2,3})(-([A-Za-z]{2}|[0-9]{3}))?).*")
TESTABLES_BY_UID: dict[str, type["Testable"]] = {}


class TestableMeta(ABCMeta):
    def __init__(cls, name: str, bases: tuple[type, ...], clsdict: dict[str, object]) -> None:
        super().__init__(name, bases, clsdict)
        if getattr(cls, "__abstractmethods__", None):
            return
        uid = clsdict.get("uid")
        if not isinstance(uid, str):
            raise TypeError(f"Testable {name} must define a unique UID for serialization")
        if len(uid) != 1:
            raise TypeError(f"{name}.uid must be exactly one character")
        if uid in TESTABLES_BY_UID:
            owner = TESTABLES_BY_UID[uid].__name__
            raise TypeError(f"{name}'s UID of {uid!r} is already registered by {owner}")
        TESTABLES_BY_UID[uid] = cast(type["Testable"], cls)


class Testable(metaclass=TestableMeta):
    uid: ClassVar[str]

    @abstractmethod
    def match(self, cpe: "CPE") -> bool:
        raise NotImplementedError

    @abstractmethod
    def dump_content(self, stream: TextIO) -> None:
        raise NotImplementedError

    def dump(self, stream: TextIO) -> None:
        """Write this expression's type marker and serialized content."""
        stream.write(self.uid)
        self.dump_content(stream)

    def dumps(self) -> str:
        """Return the serialized expression."""
        stream = StringIO()
        self.dump(stream)
        return stream.getvalue()

    @staticmethod
    def load(stream: TextIO) -> "Testable":
        """Read one expression from a stream.

        Raises:
            ValueError: The type marker is missing or unrecognized.
        """
        uid = stream.read(1)
        if uid not in TESTABLES_BY_UID:
            raise ValueError(f"Unknown serialized CPE expression marker {uid!r}")
        return TESTABLES_BY_UID[uid].load_content(stream)

    @staticmethod
    def loads(serialized: str) -> "Testable":
        """Read one expression from its serialized representation."""
        return Testable.load(StringIO(serialized))

    @classmethod
    @abstractmethod
    def load_content(cls, stream: TextIO) -> "Testable":
        raise NotImplementedError

    @abstractmethod
    def vulnerable_cpes(self) -> Iterator["CPE"]:
        raise NotImplementedError


class Part(Enum):
    HARDWARE = "h"
    OS = "o"
    APP = "a"

    def __str__(  # ty: ignore[missing-override-decorator]  # No override in Python 3.10.
        self,
    ) -> str:
        return self.value


class Logical(Enum):
    ANY = "*"
    NA = "-"

    def __str__(  # ty: ignore[missing-override-decorator]  # No override in Python 3.10.
        self,
    ) -> str:
        return self.value


def _language_region(region: str | int | None) -> str | int | None:
    if region is None or region == "":
        return None
    if isinstance(region, str):
        if re.fullmatch(r"[A-Za-z]{2}", region):
            return region.lower()
        if re.fullmatch(r"[0-9]{3}", region):
            return int(region)
    if isinstance(region, int) and not isinstance(region, bool) and 0 <= region <= 999:
        return region
    raise ValueError(f"Invalid language region {region!r}; use two letters or three digits")


class Language:
    def __init__(self, iso_639_code: str, region: str | int | None = None) -> None:
        if not re.fullmatch(r"[A-Za-z]{2,3}", iso_639_code):
            raise ValueError(f"Invalid ISO 639 language code: {iso_639_code!r}")
        self.code = iso_639_code.lower()
        self.region = _language_region(region)

    def __eq__(  # ty: ignore[missing-override-decorator]  # No override in Python 3.10.
        self, other: object
    ) -> bool:
        if isinstance(other, Language):
            return self.code == other.code and self.region == other.region
        return isinstance(other, str) and str(self) == other

    def __hash__(  # ty: ignore[missing-override-decorator]  # No override in Python 3.10.
        self,
    ) -> int:
        return hash(str(self))

    def __lt__(self, other: "Language | str") -> bool:
        return str(self) < str(other)

    def __str__(  # ty: ignore[missing-override-decorator]  # No override in Python 3.10.
        self,
    ) -> str:
        if self.region is None:
            return self.code
        if isinstance(self.region, int):
            return f"{self.code}-{self.region:03}"
        return f"{self.code}-{self.region}"

    def __repr__(  # ty: ignore[missing-override-decorator]  # No override in Python 3.10.
        self,
    ) -> str:
        return f"{self.__class__.__name__}(iso_639_code={self.code!r}, region={self.region!r})"


AVString = str | Logical
AttributeValue = str | Logical | Part | Language


class TestError(ValueError):
    """A CPE comparison cannot be established from the supplied values."""


def _attribute_tokens(value: str) -> list[tuple[str, bool]]:
    tokens: list[tuple[str, bool]] = []
    index = 0
    while index < len(value):
        character = value[index]
        escaped = character == "\\"
        if escaped:
            index += 1
            if index == len(value):
                raise TestError(f"Invalid trailing escape in CPE attribute {value!r}")
            character = value[index]
        tokens.append((character.lower(), escaped))
        index += 1
    return tokens


def _wildcard_pattern(value: str) -> str:
    if not value:
        return ""
    if value == "*":
        return ".*"
    if any(character != "?" for character in value):
        raise TestError("A CPE source wildcard must be one '*' or a sequence of '?' characters")
    return f".{{0,{len(value)}}}"


def _source_pattern(tokens: list[tuple[str, bool]]) -> str:
    wildcard = [character in "*?" and not escaped for character, escaped in tokens]
    literals = [index for index, is_wildcard in enumerate(wildcard) if not is_wildcard]
    if not literals:
        if tokens == [("*", False)]:
            return ".*"
        raise TestError("A CPE string pattern must contain a literal attribute value")
    first, last = literals[0], literals[-1]
    if any(wildcard[first : last + 1]):
        raise TestError("CPE source wildcards are allowed only at the start or end of an attribute")
    prefix = _wildcard_pattern("".join(character for character, _ in tokens[:first]))
    suffix = _wildcard_pattern("".join(character for character, _ in tokens[last + 1 :]))
    literal = "".join(re.escape(character) for character, _ in tokens[first : last + 1])
    return prefix + literal + suffix


def _match_attribute(source: AttributeValue, target: AttributeValue) -> bool:
    target_tokens = _attribute_tokens(target) if isinstance(target, str) else []
    if any(character in "*?" and not escaped for character, escaped in target_tokens):
        raise TestError(
            "CPE target attributes cannot contain unescaped wildcards; use a source pattern"
        )
    if source == Logical.ANY:
        return True
    if source == Logical.NA:
        return target == Logical.NA
    if target == Logical.ANY:
        return True
    if target == Logical.NA:
        return False
    if isinstance(source, str) and isinstance(target, str):
        pattern = _source_pattern(_attribute_tokens(source))
        text = "".join(character for character, _ in target_tokens)
        return re.fullmatch(pattern, text) is not None
    return source == target


@dataclass(unsafe_hash=True, frozen=True, order=True)
class CPE(Testable):
    uid: ClassVar[str] = "c"
    part: Part | Logical = Logical.ANY
    vendor: AVString = Logical.ANY
    product: AVString = Logical.ANY
    version: AVString = Logical.ANY
    update: AVString = Logical.ANY
    edition: AVString = Logical.ANY
    lang: Language | Logical = Logical.ANY
    sw_edition: AVString = Logical.ANY
    target_sw: AVString = Logical.ANY
    target_hw: AVString = Logical.ANY
    other: AVString = Logical.ANY

    def is_complete_wildcard(self) -> bool:
        return all(getattr(self, field.name) == Logical.ANY for field in fields(self))

    @staticmethod
    def _match(source: AttributeValue, target: AttributeValue) -> bool:
        return _match_attribute(source, target)

    def match(  # ty: ignore[missing-override-decorator]  # No override in Python 3.10.
        self, cpe: "CPE", match_version: bool = True
    ) -> bool:
        """Compare this source criterion with a target name or unconstrained filter.

        Source strings use case-insensitive CPE wildcard rules. Target strings
        must not contain unescaped wildcards. Logical ANY in a target leaves that
        component unconstrained for candidate searches.

        Raises:
            TestError: A source pattern is invalid or a target contains wildcards.
        """
        for field in fields(self):
            if field.name != "version" or match_version:
                if not _match_attribute(getattr(self, field.name), getattr(cpe, field.name)):
                    return False
        return True

    def formatted_string(self) -> str:
        """Return the CPE 2.3 formatted string binding."""
        return "cpe:2.3:" + ":".join(str(getattr(self, field.name)) for field in fields(self))

    __str__ = formatted_string

    def dump_content(  # ty: ignore[missing-override-decorator]  # No override in Python 3.10.
        self, stream: TextIO
    ) -> None:
        stream.write(self.formatted_string())
        stream.write("\n")

    @classmethod
    def load_content(  # ty: ignore[missing-override-decorator]  # No override in Python 3.10.
        cls, stream: TextIO
    ) -> "CPE":
        line = stream.readline()
        if line.endswith("\n"):
            line = line[:-1].removesuffix("\r")
        return parse_formatted_string(line)

    def vulnerable_cpes(  # ty: ignore[missing-override-decorator]  # No override in Python 3.10.
        self,
    ) -> Iterator["CPE"]:
        yield self


class FormattedStringError(ValueError):
    pass


class ParseContext:
    def __init__(self, parser: "FormattedStringParser") -> None:
        self.parser = parser
        self._start_offset = parser.offset

    def __enter__(self) -> "FormattedStringParser":
        self._start_offset = self.parser.offset
        return self.parser

    def __exit__(self, exc_type: object, exc_val: object, exc_tb: object) -> None:
        if exc_type is not None or exc_val is not None or exc_tb is not None:
            self.parser.offset = self._start_offset


class FormattedStringParser:
    def __init__(self, fs: str) -> None:
        self.fs = fs
        self.offset = 0

    def context(self) -> ParseContext:
        return ParseContext(self)

    def error(self, expected: str) -> NoReturn:
        if self.offset >= len(self.fs):
            raise FormattedStringError(f"Reached the end of the CPE while expecting {expected!r}")
        found = self.fs[self.offset : self.offset + len(expected)]
        raise FormattedStringError(
            f"Expected {expected!r} at CPE offset {self.offset}, found {found!r}"
        )

    def expect(self, text: str) -> None:
        if self.fs[self.offset : self.offset + len(text)] != text:
            self.error(text)
        self.offset += len(text)

    def up_to(self, delimiter: str, consume_delimiter: bool = True) -> str:
        index = self.fs.find(delimiter, self.offset)
        if index < 0:
            self.error(delimiter)
        value = self.fs[self.offset : index]
        self.offset = index + (len(delimiter) if consume_delimiter else 0)
        return value

    def peek(self) -> str:
        return self.fs[self.offset : self.offset + 1]

    def parse_repeated(
        self, parser: Callable[[], str], at_least: int = 0, at_most: int | None = None
    ) -> Iterator[str]:
        if at_most is not None and at_most < at_least:
            return
        yielded = 0
        error: FormattedStringError | None = None
        while yielded < at_least and (at_most is None or yielded < at_most):
            try:
                with self.context():
                    yield parser()
                yielded += 1
            except FormattedStringError as exception:
                error = exception
                break
        if yielded < at_least and error is not None:
            raise error

    def parse_avstring(self) -> AVString:
        match = AV_STRING_REGEX.match(self.fs[self.offset :])
        if match is None:
            self.error("a CPE attribute value")
        value = cast(str, match.group(1))
        self.offset += len(value)
        if value == "*":
            return Logical.ANY
        if value == "-":
            return Logical.NA
        return value

    def parse_langtag(self) -> Language:
        match = LANGTAG_REGEX.match(self.fs[self.offset :])
        if match is None:
            self.error("a language tag")
        self.offset += len(match.group(1))
        return Language(iso_639_code=match.group(2), region=match.group(4))

    def parse_lang(self) -> Language | Logical:
        character = self.peek()
        if character in ("*", "-"):
            self.offset += 1
            return Logical(character)
        return self.parse_langtag()

    def _parse_part(self) -> Part | Logical:
        value = self.up_to(":")
        for possibility in (*Part, *Logical):
            if possibility.value == value:
                return possibility
        raise FormattedStringError(f"Invalid CPE part specifier: {value!r}")

    def _av_component(self) -> AVString:
        value = self.parse_avstring()
        self.expect(":")
        return value

    def parse(self) -> CPE:
        """Parse a complete formatted string, rejecting all trailing characters."""
        self.offset = 0
        self.expect("cpe:")
        version = self.up_to(":")
        if version != "2.3":
            raise FormattedStringError(f"Unsupported CPE version {version!r}; expected '2.3'")
        part = self._parse_part()
        vendor = self._av_component()
        product = self._av_component()
        version = self._av_component()
        update = self._av_component()
        edition = self._av_component()
        language = self.parse_lang()
        self.expect(":")
        sw_edition = self._av_component()
        target_sw = self._av_component()
        target_hw = self._av_component()
        other = self.parse_avstring()
        if self.offset != len(self.fs):
            self.error("end of formatted string")
        return CPE(
            part=part,
            vendor=vendor,
            product=product,
            version=version,
            update=update,
            edition=edition,
            lang=language,
            sw_edition=sw_edition,
            target_sw=target_sw,
            target_hw=target_hw,
            other=other,
        )


def parse_formatted_string(fs: str) -> CPE:
    """Parse one complete CPE 2.3 formatted string without a record newline."""
    return FormattedStringParser(fs).parse()


class LogicalTest(Testable, ABC):
    def __init__(self, children: Iterable[Testable], negate: bool = False) -> None:
        self.children = tuple(children)
        self.negate = negate

    def __eq__(  # ty: ignore[missing-override-decorator]  # No override in Python 3.10.
        self, other: object
    ) -> bool:
        return (
            isinstance(other, LogicalTest)
            and other.uid == self.uid
            and other.negate == self.negate
            and other.children == self.children
        )

    def __hash__(  # ty: ignore[missing-override-decorator]  # No override in Python 3.10.
        self,
    ) -> int:
        return hash((self.negate,) + self.children)

    @classmethod
    def load_content(  # ty: ignore[missing-override-decorator]  # No override in Python 3.10.
        cls, stream: TextIO
    ) -> "LogicalTest":
        negate = stream.read(1) == "~"
        num_children = int(stream.readline())
        children = [Testable.load(stream) for _ in range(num_children)]
        return cls(children, negate)

    def dump_content(  # ty: ignore[missing-override-decorator]  # No override in Python 3.10.
        self, stream: TextIO
    ) -> None:
        stream.write("~" if self.negate else "=")
        stream.write(f"{len(self.children)}\n")
        for child in self.children:
            child.dump(stream)

    def vulnerable_cpes(  # ty: ignore[missing-override-decorator]  # No override in Python 3.10.
        self,
    ) -> Iterator[CPE]:
        if not self.negate:
            for child in self.children:
                yield from child.vulnerable_cpes()


class And(LogicalTest):
    uid = "a"

    def match(  # ty: ignore[missing-override-decorator]  # No override in Python 3.10.
        self, cpe: CPE
    ) -> bool:
        result = all(child.match(cpe) for child in self.children)
        return not result if self.negate else result


class Or(LogicalTest):
    uid = "o"

    def match(  # ty: ignore[missing-override-decorator]  # No override in Python 3.10.
        self, cpe: CPE
    ) -> bool:
        result = any(child.match(cpe) for child in self.children)
        return not result if self.negate else result


class Negate(Testable):
    uid = "!"

    def __init__(self, wrapped: Testable) -> None:
        self.wrapped = wrapped

    def __eq__(  # ty: ignore[missing-override-decorator]  # No override in Python 3.10.
        self, other: object
    ) -> bool:
        return isinstance(other, Negate) and self.wrapped == other.wrapped

    def __hash__(  # ty: ignore[missing-override-decorator]  # No override in Python 3.10.
        self,
    ) -> int:
        return hash(self.wrapped)

    def match(  # ty: ignore[missing-override-decorator]  # No override in Python 3.10.
        self, cpe: CPE
    ) -> bool:
        return not self.wrapped.match(cpe)

    def dump_content(  # ty: ignore[missing-override-decorator]  # No override in Python 3.10.
        self, stream: TextIO
    ) -> None:
        self.wrapped.dump(stream)

    @classmethod
    def load_content(  # ty: ignore[missing-override-decorator]  # No override in Python 3.10.
        cls, stream: TextIO
    ) -> "Negate":
        return cls(Testable.load(stream))

    def vulnerable_cpes(  # ty: ignore[missing-override-decorator]  # No override in Python 3.10.
        self,
    ) -> Iterator[CPE]:
        return iter(())


_VERSION_PATTERN = re.compile(
    r"([0-9]+(?:\.[0-9]+)*)(?:[-_.]?(dev|alpha|a|beta|b|preview|pre|rc)(?:[-_.]?([0-9]+))?)?",
    re.IGNORECASE,
)
_PRERELEASE_RANK = {
    "dev": 0,
    "alpha": 1,
    "a": 1,
    "beta": 2,
    "b": 2,
    "preview": 3,
    "pre": 3,
    "rc": 3,
}


def _version_key(value: str) -> tuple[tuple[int, ...], int, int]:
    text = "".join(character for character, _ in _attribute_tokens(value))
    match = _VERSION_PATTERN.fullmatch(text)
    if match is None:
        raise TestError(
            f"Cannot order CPE version {value!r}; use numeric releases with an optional "
            "dev, alpha, beta, pre, preview, or rc suffix"
        )
    release = [int(component) for component in match.group(1).split(".")]
    while len(release) > 1 and release[-1] == 0:
        release.pop()
    qualifier = match.group(2)
    rank = 4 if qualifier is None else _PRERELEASE_RANK[qualifier.lower()]
    return tuple(release), rank, int(match.group(3) or "0")


def _compare_versions(left: str, right: str) -> int:
    if _attribute_tokens(left) == _attribute_tokens(right):
        return 0
    left_key, right_key = _version_key(left), _version_key(right)
    return (left_key > right_key) - (left_key < right_key)


def _load_bound(stream: TextIO) -> tuple[bool, str | None]:
    flag = stream.read(1)
    if flag not in ("I", "E"):
        raise ValueError(f"Invalid version-bound inclusion marker {flag!r}; expected 'I' or 'E'")
    line = stream.readline()
    if not line.endswith("\n"):
        raise ValueError("Incomplete serialized version bound; expected a newline-terminated value")
    return flag == "I", line[:-1].removesuffix("\r") or None


class VersionRange(Testable):
    uid = "v"

    def __init__(
        self,
        wrapped: CPE,
        start: str | None = None,
        end: str | None = None,
        include_start: bool = True,
        include_end: bool = True,
    ) -> None:
        """Initialize a range with canonical absent bounds and preserved flags.

        Empty strings mean an absent bound. Literal backslash escapes and vendor
        formats are preserved; ordering rules are applied only when matching.

        Raises:
            ValueError: A bound contains CR or LF, which cannot be represented in
                the newline-delimited serialization format.
        """
        for name, bound in (("start", start), ("end", end)):
            if bound is not None and ("\r" in bound or "\n" in bound):
                raise ValueError(
                    f"Invalid {name} version bound {bound!r}: CR/LF characters are not allowed"
                )
        self.wrapped = wrapped
        self.start = start or None
        self.end = end or None
        self.include_start = include_start
        self.include_end = include_end

    def __eq__(  # ty: ignore[missing-override-decorator]  # No override in Python 3.10.
        self, other: object
    ) -> bool:
        return (
            isinstance(other, VersionRange)
            and self.start == other.start
            and self.end == other.end
            and self.include_start == other.include_start
            and self.include_end == other.include_end
            and self.wrapped == other.wrapped
        )

    def __hash__(  # ty: ignore[missing-override-decorator]  # No override in Python 3.10.
        self,
    ) -> int:
        return hash((self.wrapped, self.start, self.end, self.include_start, self.include_end))

    def match(  # ty: ignore[missing-override-decorator]  # No override in Python 3.10.
        self, cpe: CPE
    ) -> bool:
        """Match a numeric or recognized prerelease against both range boundaries.

        Raises:
            TestError: The relevant product has versions with unknown ordering.
        """
        if not self.wrapped.match(cpe, match_version=False):
            return False
        if cpe.version == Logical.NA:
            return self.start is None and self.end is None
        if isinstance(cpe.version, str):
            if self.start is not None:
                comparison = _compare_versions(cpe.version, self.start)
                if comparison < 0 or (comparison == 0 and not self.include_start):
                    return False
            if self.end is not None:
                comparison = _compare_versions(cpe.version, self.end)
                if comparison > 0 or (comparison == 0 and not self.include_end):
                    return False
        return True

    def dump_content(  # ty: ignore[missing-override-decorator]  # No override in Python 3.10.
        self, stream: TextIO
    ) -> None:
        for bound, inclusive in ((self.start, self.include_start), (self.end, self.include_end)):
            stream.write("I" if inclusive else "E")
            if bound is not None:
                stream.write(bound)
            stream.write("\n")
        self.wrapped.dump(stream)

    @classmethod
    def load_content(  # ty: ignore[missing-override-decorator]  # No override in Python 3.10.
        cls, stream: TextIO
    ) -> "VersionRange":
        include_start, start = _load_bound(stream)
        include_end, end = _load_bound(stream)
        wrapped = Testable.load(stream)
        if not isinstance(wrapped, CPE):
            raise ValueError("A serialized version range must wrap a CPE name")
        return cls(wrapped, start, end, include_start, include_end)

    def vulnerable_cpes(  # ty: ignore[missing-override-decorator]  # No override in Python 3.10.
        self,
    ) -> Iterator[CPE]:
        yield from self.wrapped.vulnerable_cpes()
