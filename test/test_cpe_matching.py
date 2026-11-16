from io import StringIO
from unittest import TestCase

from hypothesis import given, settings, strategies as st

from cvedb.cpe import (
    CPE,
    FormattedStringError,
    Language,
    Logical,
    Negate,
    Part,
    Testable,
    TestError as CPEMatchError,
    VersionRange,
    parse_formatted_string,
)


class TestVersionRangeMatching(TestCase):
    def test_both_boundaries(self) -> None:
        for include_start in (False, True):
            for include_end in (False, True):
                criterion = VersionRange(
                    CPE(vendor="acme"), "2.0", "4.0", include_start, include_end
                )
                for version, expected in (
                    ("1.9", False),
                    ("2.0", include_start),
                    ("3.0", True),
                    ("4.0", include_end),
                    ("4.1", False),
                ):
                    with self.subTest(version=version, start=include_start, end=include_end):
                        self.assertEqual(
                            criterion.match(CPE(vendor="acme", version=version)), expected
                        )

    def test_numeric_components_and_prereleases(self) -> None:
        for lower, candidate, expected in (
            ("2.0", "10.0", True),
            ("10.0", "2.0", False),
            ("1.0.0", "1", True),
            ("1.2.3", "1.2", False),
            ("1.0", "1.0rc1", False),
            ("1.0rc1", "1.0", True),
            ("1.0rc2", "1.0rc10", True),
            ("1.0beta1", "1.0alpha9", False),
            ("1.0dev1", "1.0alpha1", True),
            (r"1.0\-rc1", "1.0rc2", True),
        ):
            with self.subTest(lower=lower, candidate=candidate):
                criterion = VersionRange(CPE(vendor="acme"), start=lower)
                self.assertEqual(criterion.match(CPE(vendor="acme", version=candidate)), expected)

    def test_unknown_vendor_ordering_is_explicit(self) -> None:
        criterion = VersionRange(CPE(vendor="acme"), start="vendor-release")
        with self.assertRaisesRegex(CPEMatchError, "Cannot order CPE version"):
            criterion.match(CPE(vendor="acme", version="next-release"))
        self.assertTrue(criterion.match(CPE(vendor="acme", version="vendor-release")))
        self.assertFalse(criterion.match(CPE(vendor="other", version="next-release")))

    def test_logical_versions(self) -> None:
        criterion = VersionRange(CPE(vendor="acme"), start="2", end="4")
        self.assertTrue(criterion.match(CPE(vendor="acme", version=Logical.ANY)))
        self.assertFalse(criterion.match(CPE(vendor="acme", version=Logical.NA)))
        self.assertTrue(VersionRange(CPE()).match(CPE(version=Logical.NA)))

    def test_all_bound_shapes_round_trip(self) -> None:
        for criterion in (
            VersionRange(CPE(vendor="acme")),
            VersionRange(CPE(vendor="acme"), start="2"),
            VersionRange(CPE(vendor="acme"), end="4", include_end=False),
            VersionRange(CPE(vendor="acme"), start="2", end="4"),
        ):
            restored = Testable.loads(criterion.dumps())
            self.assertEqual(restored, criterion)
            for version in ("1", "2", "3", "4", "5"):
                with self.subTest(criterion=criterion.dumps(), version=version):
                    candidate = CPE(vendor="acme", version=version)
                    self.assertEqual(restored.match(candidate), criterion.match(candidate))

    def test_incomplete_bounds_and_invalid_wrapped_records(self) -> None:
        for text in (
            "v",
            "vI",
            "vI\n",
            "vX2\nE4\n",
            "vI\nE\n!=0\n",
            "vI\nE\n" + Negate(CPE()).dumps(),
        ):
            with self.subTest(text=text), self.assertRaises(ValueError):
                Testable.loads(text)

    @settings(database=None, derandomize=True)
    @given(st.integers(0, 100), st.integers(0, 100), st.integers(0, 100))
    def test_numeric_bound_round_trip(self, start: int, end: int, candidate: int) -> None:
        criterion = VersionRange(CPE(), start=str(start), end=str(end))
        target = CPE(version=str(candidate))
        restored = Testable.loads(criterion.dumps())
        self.assertEqual(criterion.match(target), start <= candidate <= end)
        self.assertEqual(restored.match(target), criterion.match(target))


class TestCPEStringMatching(TestCase):
    def test_case_and_escaped_characters(self) -> None:
        for source, target, expected in (
            ("ACME", "acme", True),
            ("ac*", "acme", True),
            ("*me", "acme", True),
            ("*cm*", "acme", True),
            ("?acme", "acme", True),
            ("?acme", "xacme", True),
            ("?acme", "xxacme", False),
            ("acme??", "acme12", True),
            ("acme??", "acme123", False),
            (r"ac\*", r"AC\*", True),
            (r"ac\*", "acme", False),
            (r"ac\?", r"AC\?", True),
            (r"ac\:me", r"AC\:ME", True),
            (r"ac\\*", r"ac\\path", True),
            ("ac.me", "acXme", False),
        ):
            with self.subTest(source=source, target=target):
                self.assertEqual(CPE(vendor=source).match(CPE(vendor=target)), expected)

    def test_long_question_mark_runs(self) -> None:
        prefix = CPE(vendor="?" * 1024 + "z")
        self.assertTrue(prefix.match(CPE(vendor="a" * 1024 + "z")))
        self.assertTrue(prefix.match(CPE(vendor="z")))
        self.assertFalse(prefix.match(CPE(vendor="a" * 1024)))
        self.assertFalse(prefix.match(CPE(vendor="a" * 1025 + "z")))
        suffix = CPE(vendor="z" + "?" * 1024)
        self.assertTrue(suffix.match(CPE(vendor="z" + "a" * 1024)))
        self.assertFalse(suffix.match(CPE(vendor="z" + "a" * 1025)))
        both = CPE(vendor="?" * 1024 + "z" + "?" * 1024)
        self.assertTrue(both.match(CPE(vendor="a" * 1024 + "z" + "b" * 1024)))
        self.assertFalse(both.match(CPE(vendor="a" * 2048)))

    def test_non_vendor_fields(self) -> None:
        source = CPE(product="WIDGET*", update="SP?", edition=r"pro\+", target_hw="X86*")
        target = CPE(product="widget_x", update="sp1", edition=r"PRO\+", target_hw="x86_64")
        self.assertTrue(source.match(target))
        self.assertFalse(source.match(CPE(product="different")))

    def test_target_wildcard_is_not_a_concrete_comparison(self) -> None:
        for source in (CPE(), CPE(vendor="acme"), CPE(vendor="ac*")):
            with self.subTest(source=source), self.assertRaisesRegex(CPEMatchError, "target"):
                source.match(CPE(vendor="ac*"))

    def test_invalid_source_patterns(self) -> None:
        for source in ("", "??", "ac*me", "ac?me", "**acme", "*?acme", "acme\\"):
            with self.subTest(source=source), self.assertRaises(CPEMatchError):
                CPE(vendor=source).match(CPE(vendor="acme"))

    def test_logical_values(self) -> None:
        for source, target, expected in (
            (Logical.ANY, Logical.ANY, True),
            (Logical.ANY, Logical.NA, True),
            (Logical.ANY, "acme", True),
            (Logical.NA, Logical.NA, True),
            (Logical.NA, "acme", False),
            ("acme", Logical.ANY, True),
            ("acme", Logical.NA, False),
        ):
            with self.subTest(source=source, target=target):
                self.assertEqual(CPE(vendor=source).match(CPE(vendor=target)), expected)


class TestFormattedCPEInput(TestCase):
    def test_rejects_all_trailing_input(self) -> None:
        valid = "cpe:2.3:a:acme:widget:1:*:*:*:*:*:*:final"
        self.assertEqual(parse_formatted_string(valid).other, "final")
        for suffix in (":extra", " invalid", "\n", "\t", "\r", "\\"):
            with self.subTest(suffix=suffix), self.assertRaises(FormattedStringError):
                parse_formatted_string(valid + suffix)

    def test_serialized_newline_is_explicit(self) -> None:
        source = CPE(vendor=r"ac\:me", other=r"last\*")
        stream = StringIO(source.dumps() + CPE(part=Part.OS).dumps())
        self.assertEqual(Testable.load(stream), source)
        self.assertEqual(Testable.load(stream), CPE(part=Part.OS))
        self.assertEqual(Testable.loads(source.dumps().replace("\n", "\r\n")), source)

    def test_rejects_missing_fields_and_unescaped_delimiters(self) -> None:
        for text in (str(CPE())[:-2], "cpe:2.3:a:ac:me:product:1:*:*:*:*:*:*:*"):
            with self.subTest(text=text), self.assertRaises(FormattedStringError):
                parse_formatted_string(text)

    @settings(database=None, derandomize=True)
    @given(st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789._-", min_size=2, max_size=30))
    def test_formatted_strings_round_trip(self, value: str) -> None:
        criterion = CPE(vendor=value, product="widget", other=r"literal\?\*")
        self.assertEqual(parse_formatted_string(str(criterion)), criterion)
        self.assertEqual(Testable.loads(criterion.dumps()), criterion)
        with self.assertRaises(FormattedStringError):
            parse_formatted_string(str(criterion) + ":extra")


class TestLanguageValues(TestCase):
    def test_canonical_values_have_equal_hashes(self) -> None:
        for value in (Language("EN"), Language("EN", "US"), Language("es", "005")):
            text = str(value)
            self.assertEqual(value, text)
            self.assertEqual(text, value)
            self.assertEqual(value, Language(value.code, value.region))
            self.assertEqual(hash(value), hash(text))
            self.assertEqual(len({value, text}), 1)
            lookup: dict[Language | str, str] = {value: "found"}
            self.assertEqual(lookup[text], "found")
        self.assertNotEqual(Language("en"), "EN")

    def test_constructor_validation(self) -> None:
        for code in ("12", "a", "abcd", "éé", "en "):
            with self.subTest(code=code), self.assertRaises(ValueError):
                Language(code)
        for region in ("1a", "12", "0000", -1, 1000, True):
            with self.subTest(region=region), self.assertRaises(ValueError):
                Language("en", region)

    def test_region_forms_and_parser_agree(self) -> None:
        for region, expected in ((None, "en"), ("", "en"), ("US", "en-us"), ("005", "en-005")):
            value = Language("EN", region)
            self.assertEqual(str(value), expected)
            self.assertEqual(parse_formatted_string(str(CPE(lang=value))).lang, value)
        self.assertEqual(Language("en", 5), Language("en", "005"))


class TestVersionRangeBoundEncoding(TestCase):
    def test_empty_constructor_bounds_are_canonical_and_round_trip(self) -> None:
        for start, end in (("", None), (None, ""), ("", ""), ("", "4"), ("2", "")):
            for include_start in (False, True):
                for include_end in (False, True):
                    with self.subTest(start=start, end=end, flags=(include_start, include_end)):
                        original = VersionRange(CPE(), start, end, include_start, include_end)
                        self.assertEqual(original.start, start or None)
                        self.assertEqual(original.end, end or None)
                        restored = Testable.loads(original.dumps())
                        self.assertEqual(original, restored)
                        assert isinstance(restored, VersionRange)
                        self.assertEqual(restored.include_start, include_start)
                        self.assertEqual(restored.include_end, include_end)
                        for version in ("1", "2", "3", "4", "5"):
                            candidate = CPE(version=version)
                            self.assertEqual(original.match(candidate), restored.match(candidate))

    def test_constructor_rejects_line_breaks_with_bound_and_input_context(self) -> None:
        for name in ("start", "end"):
            for value in ("2\n3", "2\r3", "\n2", "2\n", "\r2", "2\r", "\n", "\r"):
                with self.subTest(name=name, value=value):
                    with self.assertRaises(ValueError) as raised:
                        if name == "start":
                            VersionRange(CPE(), start=value)
                        else:
                            VersionRange(CPE(), end=value)
                    self.assertIn(name, str(raised.exception))
                    self.assertIn(repr(value), str(raised.exception))

    def test_literal_escapes_and_unknown_vendor_bounds_are_preserved(self) -> None:
        for value in (r"vendor\nrelease", r"vendor\rrelease", "vendor-release"):
            with self.subTest(value=value):
                original = VersionRange(CPE(), value, value)
                self.assertEqual(original.start, value)
                self.assertEqual(original.end, value)
                restored = Testable.loads(original.dumps())
                self.assertEqual(original, restored)
                self.assertTrue(original.match(CPE(version=value)))
                self.assertTrue(restored.match(CPE(version=value)))
                with self.assertRaises(CPEMatchError):
                    original.match(CPE(version="2"))
