from io import StringIO
import re
from shutil import get_terminal_size, which
from subprocess import PIPE, Popen
import sys
from typing import Callable, Iterable, List, Optional, TextIO

from .cve import CVE, Severity


CVE_ID_WIDTH: int = 17


SEVERITY_COLORS = {
    Severity.UNKNOWN:  "\033[34;1m",  # Blue
    Severity.NONE:     "\033[37;1m",  # White
    Severity.LOW:      "\033[36;1m",  # Cyan
    Severity.MEDIUM:   "\033[33;1m",  # Yellow
    Severity.HIGH:     "\033[31;1m",  # Red
    Severity.CRITICAL: "\033[35;1m"   # Magenta
}


STRIP_ANSI_REGEX = re.compile(r"""
    \x1b     # literal ESC
    \[       # literal [
    [;\d]*   # zero or more digits or semicolons
    [A-Za-z] # a letter
""", re.VERBOSE).sub


def strip_ansi(text: str):
    return STRIP_ANSI_REGEX("", text)


def ansi_len(text: str):
    """Counts the length of a string not counting any ANSI excape characters"""
    return len(strip_ansi(text))


def _print_box_row(
        stream: TextIO,
        columns: int,
        text: str,
        right_text: str = "",
        center: bool = False,
        word_wrap: bool = False,
        hang_indent: str = "",
        text_splitter: Optional[Callable[[str], List[str]]] = lambda s: s.split(" "),
        delimiter: str = " ",
        line_pre: str = "",
        line_post: str = "",
        prefix: str = "",
        left_edge: str = "║",
        right_edge: str = "║"
):
    left_len = ansi_len(text)
    right_len = ansi_len(right_text)
    text_len = left_len + right_len + ansi_len(prefix)
    if text_len >= columns - 2:
        if word_wrap:
            desc_words = text_splitter(text)
            if right_text:
                desc_words += text_splitter(right_text)
            lines = [prefix]
            for word in desc_words:
                if lines[-1]:
                    new_line = f"{lines[-1]}{delimiter}{word}"
                    if ansi_len(f"{line_pre}{new_line}{line_post}") > columns - 2:
                        new_line = f"{hang_indent}{word}"
                        lines.append("")
                else:
                    new_line = word
                lines[-1] = new_line
            for line in lines:
                _print_box_row(stream, columns, f"{line_pre}{line}{line_post}")
            return
        else:
            stream.write(left_edge)
            stream.write(prefix)
            stream.write(text)
            stream.write(right_text)
    elif center:
        stream.write(left_edge)
        padding = (columns - 2 - text_len) // 2
        stream.write(" " * padding)
        stream.write(prefix)
        stream.write(text)
        stream.write(right_text)
        stream.write(" " * (columns - 2 - text_len - padding))
    else:
        stream.write(left_edge)
        stream.write(prefix)
        stream.write(text)
        stream.write(" " * (columns - 2 - text_len))
        stream.write(right_text)
    stream.write(f"{right_edge}\n")


def split_url(url: str) -> List[str]:
    ret = []
    while url:
        i = url.find("/")
        if i >= 0:
            ret.append(url[:i+1])
            url = url[i+1:]
        else:
            ret.append(url)
            break
    return ret


def print_cve_tty(cve: CVE, stream: TextIO, term_columns: Optional[int] = None):
    if term_columns is None:
        actual_columns = get_terminal_size((80, 20)).columns
    else:
        actual_columns = term_columns
    columns = max(45, actual_columns)
    stream.write("╔")
    seps_before = (actual_columns - 4 - len(cve.cve_id)) // 2
    stream.write("═" * seps_before)
    color = SEVERITY_COLORS[cve.severity]
    stream.write(f"╡{color}{cve.cve_id}\033[0m╞")
    stream.write("═" * (actual_columns - seps_before - 4 - len(cve.cve_id)))
    stream.write("╗\n")
    _print_box_row(stream, columns, f" Published: \033[7m{cve.published_date.strftime('%Y-%m-%d')}\033[0m",
                   right_text=f" Modified: \033[7m{cve.last_modified_date.strftime('%Y-%m-%d')}\033[0m ")
    if cve.impact is None:
        impact_text = "????"
    else:
        impact_text = f"{cve.impact.base_score:02.1f}"
        if len(impact_text) < 4:
            impact_text += " " * (4 - len(impact_text))
    _print_box_row(stream, columns, f"  Severity: {color}\033[7m{cve.severity.name}\033[0m",
                   right_text=f" Impact: {color}\033[7m{impact_text}\033[0m       ")
    _print_box_row(stream, actual_columns, "─" * (actual_columns - 2), left_edge="╟", right_edge="╢")
    _print_box_row(stream, columns, cve.description(), word_wrap=True, line_pre="\033[3m\033[1m", line_post="\033[0m")
    if cve.references:
        _print_box_row(stream, actual_columns, "─" * (actual_columns - 2), left_edge="╟", right_edge="╢")
        _print_box_row(stream, columns, " \033[4mReferences\033[0m")
        for ref in cve.references:
            _print_box_row(stream, columns, f"{ref.name}", word_wrap=True, hang_indent="    ", prefix="  • ")
            if ref.url != ref.name:
                _print_box_row(stream, columns, f"{ref.url}", word_wrap=True, hang_indent="    ", prefix="    ",
                               text_splitter=split_url, delimiter="")
            # TODO: Use this if/when `less -R` adds support for hyperlinks:
            # _print_box_row(stream, columns, f"  • \033]8;;{ref.url}\033\\{ref.name}\033]8;;\033\\")
    stream.write("╚")
    stream.write("═" * (actual_columns - 2))
    stream.write("╝")


def print_cve_notty(cve: CVE, stream: TextIO):
    stream.write(f"{cve.cve_id}\t{cve.description()}\n")


def print_cves(cves: Iterable[CVE], force_color: Optional[bool] = None):
    if force_color is None:
        force_color = sys.stdout.isatty() and sys.stderr.isatty()

    if not force_color:
        for cve in cves:
            print_cve_notty(cve, sys.stdout)
        return

    term_size = get_terminal_size((80, 20))

    pager = which("less")

    if pager is None:
        for cve in cves:
            print_cve_tty(cve, sys.stdout, term_size.columns)
        return

    # expand some CVEs to see if we need to use a pager
    buffer = StringIO()
    pager_proc: Optional[Popen] = None

    for cve in cves:
        print_cve_tty(cve, buffer, term_size.columns)
        if pager_proc is not None:
            pager_proc.stdin.write(buffer.getvalue().encode("utf-8"))
            buffer = StringIO()
        else:
            if pager_proc is None and buffer.getvalue().count("\n") + 1 >= term_size.lines:
                # we need to use a pager
                pager_proc = Popen([pager, "-R"], stdin=PIPE)
                pager_proc.stdin.write(buffer.getvalue().encode("utf-8"))
                buffer = StringIO()

    if pager_proc is None:
        # we didn't need a pager because everything will fit in the terminal
        sys.stdout.write(buffer.getvalue())
    else:
        pager_proc.stdin.close()
        pager_proc.wait()
