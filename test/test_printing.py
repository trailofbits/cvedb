"""Behavior tests for safe, width-aware CVE output."""

from datetime import datetime, timezone
from io import BytesIO, StringIO
from os import terminal_size
from unittest import TestCase
from unittest.mock import MagicMock, patch

from cvedb.cve import CVE, Description, Reference
from cvedb.printing import ansi_len, print_cve_notty, print_cve_tty, print_cves, strip_ansi


NOW = datetime(2020, 1, 2, tzinfo=timezone.utc)


def record(
    *, descriptions: tuple[Description, ...] = (), references: tuple[Reference, ...] = ()
) -> CVE:
    """Build a record with predictable display values."""
    return CVE("CVE-2020-0001", NOW, NOW, descriptions=descriptions, references=references)


class TestDescriptions(TestCase):
    def test_missing_description_has_explicit_display_value(self) -> None:
        for renderer in (print_cve_notty, print_cve_tty):
            with self.subTest(renderer=renderer.__name__):
                stream = StringIO()
                renderer(record(), stream)
                self.assertIn("No description available", strip_ansi(stream.getvalue()))
                self.assertNotIn("None", stream.getvalue())

    def test_first_available_language_is_used_without_english(self) -> None:
        cve = record(descriptions=(Description("fr", "bonjour"), Description("de", "hallo")))
        for renderer in (print_cve_notty, print_cve_tty):
            stream = StringIO()
            renderer(cve, stream)
            self.assertIn("bonjour", strip_ansi(stream.getvalue()))

    def test_english_is_preferred_over_the_first_language(self) -> None:
        cve = record(descriptions=(Description("fr", "bonjour"), Description("en", "hello")))
        stream = StringIO()
        print_cve_notty(cve, stream)
        self.assertEqual(stream.getvalue(), "CVE-2020-0001\thello\n")

    def test_forced_ansi_and_plain_use_the_same_fallback(self) -> None:
        for color in (False, True):
            with self.subTest(color=color), patch("cvedb.printing.which", return_value=None):
                stream = StringIO()
                with patch("cvedb.printing.sys.stdout", stream):
                    print_cves([record()], force_color=color)
                self.assertIn("No description available", strip_ansi(stream.getvalue()))

    def test_automatic_color_requires_both_output_streams_to_be_terminals(self) -> None:
        for stdout_tty, stderr_tty in ((False, False), (False, True), (True, False), (True, True)):
            stdout = StringIO()
            stderr = StringIO()
            with (
                self.subTest(stdout=stdout_tty, stderr=stderr_tty),
                patch.object(stdout, "isatty", return_value=stdout_tty),
                patch.object(stderr, "isatty", return_value=stderr_tty),
                patch("cvedb.printing.sys.stdout", stdout),
                patch("cvedb.printing.sys.stderr", stderr),
                patch("cvedb.printing.which", return_value=None),
            ):
                print_cves([record()])
                self.assertEqual("\x1b[" in stdout.getvalue(), stdout_tty and stderr_tty)


class TestTerminalSafety(TestCase):
    def test_plain_output_escapes_controls_and_keeps_one_record_per_line(self) -> None:
        description = "avant\x1b]0;title\x07\r\nafter\t\x85雪"
        stream = StringIO()
        print_cve_notty(record(descriptions=(Description("en", description),)), stream)
        output = stream.getvalue()
        self.assertEqual(len(output.splitlines()), 1)
        self.assertEqual(output.count("\t"), 1)
        self.assertIn(r"avant\x1b]0;title\x07\r\nafter\t\x85雪", output)
        self.assertNotIn("\x1b", output)

    def test_tty_escapes_identifiers_descriptions_and_references(self) -> None:
        payload = "\x1b[2J\x1b]8;;https://example\x07\x9b31m\x00\x7f\r\n\t"
        cve = CVE(
            "CVE" + payload,
            NOW,
            NOW,
            descriptions=(Description("en", "雪" + payload),),
            references=(Reference(url="https://example/" + payload, name="ref" + payload),),
        )
        stream = StringIO()
        print_cve_tty(cve, stream, 80)
        output = stream.getvalue()
        plain = strip_ansi(output)
        self.assertIn("\x1b[", output)
        self.assertIn(r"\x1b", plain)
        self.assertIn("雪", plain)
        self.assertNotRegex(plain.replace("\n", ""), r"[\x00-\x1f\x7f-\x9f]")
        self.assertNotIn(payload, output)

    def test_unicode_line_separators_do_not_split_plain_records(self) -> None:
        stream = StringIO()
        print_cve_notty(record(descriptions=(Description("en", "a\u2028b\u2029c"),)), stream)
        output = stream.getvalue()
        self.assertEqual(len(output.splitlines()), 1)
        self.assertIn(r"a\u2028b\u2029c", output)

    def test_every_c0_c1_and_delete_control_is_escaped(self) -> None:
        controls = "".join(chr(number) for number in [*range(32), *range(127, 160)])
        stream = StringIO()
        print_cve_notty(record(descriptions=(Description("en", controls),)), stream)
        body = stream.getvalue().split("\t", 1)[1].removesuffix("\n")
        self.assertNotRegex(body, r"[\x00-\x1f\x7f-\x9f]")
        self.assertIn(r"\x00", body)
        self.assertIn(r"\x9f", body)

    def test_nullable_references_do_not_render_none(self) -> None:
        cve = record(references=(Reference(), Reference(url="https://example")))
        stream = StringIO()
        print_cve_tty(cve, stream, 80)
        self.assertNotIn("None", stream.getvalue())
        self.assertIn("https://example", stream.getvalue())

    def test_paged_output_uses_the_same_safe_renderer(self) -> None:
        process = MagicMock()
        process.stdin = BytesIO()
        process.__enter__.return_value = process
        cve = record(descriptions=(Description("fr", "bonjour\x1b]0;title\x07"),))
        with (
            patch("cvedb.printing.which", return_value="/usr/bin/less"),
            patch("cvedb.printing.get_terminal_size", return_value=terminal_size((80, 1))),
            patch("cvedb.printing.Popen", return_value=process),
        ):
            print_cves(
                [cve, record(descriptions=(Description("en", "second record"),))], force_color=True
            )
        output = process.stdin.getvalue().decode()
        self.assertEqual(output.count("second record"), 1)
        self.assertEqual(output.count("bonjour"), 1)
        self.assertIn("bonjour", output)
        self.assertIn(r"\x1b]0;title\x07", output)
        self.assertNotIn("\x1b]0;title\x07", output)

    def test_small_styled_output_does_not_start_a_pager(self) -> None:
        stream = StringIO()
        with (
            patch("cvedb.printing.sys.stdout", stream),
            patch("cvedb.printing.which", return_value="/usr/bin/less"),
            patch("cvedb.printing.get_terminal_size", return_value=terminal_size((80, 100))),
            patch("cvedb.printing.Popen") as spawn,
        ):
            print_cves([record()], force_color=True)
        spawn.assert_not_called()
        self.assertIn("No description available", strip_ansi(stream.getvalue()))

    def test_empty_styled_output_does_not_start_a_pager(self) -> None:
        stream = StringIO()
        with (
            patch("cvedb.printing.sys.stdout", stream),
            patch("cvedb.printing.which", return_value="/usr/bin/less"),
            patch("cvedb.printing.Popen") as spawn,
        ):
            print_cves([], force_color=True)
        spawn.assert_not_called()
        self.assertEqual(stream.getvalue(), "")

    def test_missing_pager_input_has_an_actionable_error(self) -> None:
        process = MagicMock()
        process.stdin = None
        process.__enter__.return_value = process
        with (
            patch("cvedb.printing.which", return_value="/usr/bin/less"),
            patch("cvedb.printing.get_terminal_size", return_value=terminal_size((80, 1))),
            patch("cvedb.printing.Popen", return_value=process),
            self.assertRaisesRegex(RuntimeError, "pager has no input pipe"),
        ):
            print_cves([record()], force_color=True)


class TestTerminalWidths(TestCase):
    def test_all_rows_use_the_requested_width(self) -> None:
        cve = record(
            descriptions=(Description("en", "雪e\u0301 " * 20 + "A" * 100),),
            references=(Reference(url="https://example/" + "part/" * 20, name="reference"),),
        )
        for columns in (4, 8, 20, 44, 45, 80):
            with self.subTest(columns=columns):
                stream = StringIO()
                print_cve_tty(cve, stream, columns)
                lines = stream.getvalue().splitlines()
                self.assertGreater(len(lines), 3)
                self.assertTrue(all(ansi_len(line) == columns for line in lines))

    def test_widths_below_four_use_a_consistent_four_column_box(self) -> None:
        for columns in (0, 1, 2, 3):
            stream = StringIO()
            print_cve_tty(record(), stream, columns)
            self.assertTrue(all(ansi_len(line) == 4 for line in stream.getvalue().splitlines()))

    def test_unicode_display_width_ignores_combining_marks(self) -> None:
        self.assertEqual(ansi_len("雪e\u0301"), 3)
        self.assertEqual(ansi_len("\x1b[1m雪e\u0301\x1b[0m"), 3)

    def test_multiple_records_are_separated_by_newlines(self) -> None:
        stream = StringIO()
        print_cve_tty(record(), stream, 80)
        print_cve_tty(record(), stream, 80)
        self.assertNotIn("╝╔", stream.getvalue())
