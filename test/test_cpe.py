from random import choice, randint
from typing import Callable, TypeVar, Union
from unittest import TestCase

from rstr import xeger

from cvedb.cpe import (
    AV_STRING_REGEX, CPE, FormattedStringParser, LANGTAG_REGEX, Language, Logical, parse_formatted_string, Part
)


assert AV_STRING_REGEX.pattern.endswith(".*")
assert LANGTAG_REGEX.pattern.endswith(".*")


def random_avstring() -> str:
    return xeger(AV_STRING_REGEX.pattern[:-2])


def random_language() -> Language:
    while True:
        try:
            return FormattedStringParser(xeger(LANGTAG_REGEX.pattern[:-2])).parse_langtag()
        except ValueError:
            pass


T = TypeVar("T")


def random_logical_or(gen: Callable[[], T] = random_avstring) -> Union[Logical, T]:
    r = randint(0, 2)
    if r == 0:
        return Logical.ANY
    elif r == 1:
        return Logical.NA
    while True:
        ret = gen()
        if ret != Logical.ANY.value and ret != Logical.NA.value:
            return ret


def random_cpe() -> CPE:
    return CPE(
        part=random_logical_or(lambda: choice(list(Part))),
        vendor=random_logical_or(),
        product=random_logical_or(),
        version=random_logical_or(),
        update=random_logical_or(),
        edition=random_logical_or(),
        lang=random_logical_or(random_language),
        sw_edition=random_logical_or(),
        target_sw=random_logical_or(),
        target_hw=random_logical_or(),
        other=random_logical_or()
    )


class TestCPE(TestCase):
    def test_parse(self):
        cpe = parse_formatted_string("cpe:2.3:a:kamadak-exif_project:kamadak-exif:0.5.2:*:*:*:*:rust:*:*")
        self.assertEqual(cpe.part, Part.APP)
        self.assertEqual(cpe.vendor, "kamadak-exif_project")
        self.assertEqual(cpe.product, "kamadak-exif")
        self.assertEqual(cpe.version, "0.5.2")
        self.assertEqual(cpe.update, Logical.ANY)
        self.assertEqual(cpe.edition, Logical.ANY)
        self.assertEqual(cpe.lang, Logical.ANY)
        self.assertEqual(cpe.sw_edition, Logical.ANY)
        self.assertEqual(cpe.target_sw, "rust")
        self.assertEqual(cpe.target_hw, Logical.ANY)
        self.assertEqual(cpe.other, Logical.ANY)

    def test_serialization(self):
        for i in range(100):
            cpe = random_cpe()
            self.assertEqual(cpe, CPE.loads(cpe.dumps()))

    def test_wildcards(self):
        self.assertTrue(CPE().is_complete_wildcard())
        self.assertFalse(CPE(vendor="foo").is_complete_wildcard())
