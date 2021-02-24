from io import StringIO
from shutil import get_terminal_size, which
from subprocess import PIPE, Popen
import sys
from typing import Iterable, Optional, TextIO

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


def print_cve_tty(cve: CVE, stream: TextIO, term_columns: Optional[int] = None):
    if term_columns is None:
        columns = get_terminal_size((80, 20)).columns
    else:
        columns = term_columns
    desc_words = cve.description().split(" ")
    lines = [""]
    for word in desc_words:
        if lines[-1]:
            new_line = f"{lines[-1]} {word}"
            if len(new_line) + CVE_ID_WIDTH > columns:
                new_line = word
                lines.append("")
        else:
            new_line = word
        lines[-1] = new_line
    cve_id = cve.cve_id
    if len(cve_id) < CVE_ID_WIDTH:
        cve_id = f"{cve_id}{' ' * (CVE_ID_WIDTH - len(cve_id))}"
    color = SEVERITY_COLORS[cve.severity]
    stream.write(f"{color}{cve_id}\033[0m\033[3m\033[37;1m{lines[0]}\033[23m\033[0m\n")
    if len(lines) < 3:
        lines += [""] * (3 - len(lines))
    for i, line in enumerate(lines[1:]):
        if i == 0:
            prefix = cve.severity.name
        elif i == 1 and cve.impact is not None:
            prefix = f"Impact: {cve.impact.base_score:.1f}"
        else:
            prefix = " " * CVE_ID_WIDTH
        if len(prefix) < CVE_ID_WIDTH:
            prefix += " " * (CVE_ID_WIDTH - len(prefix))
        stream.write(f"{color}{prefix}\033[0m\033[3m\033[37;1m{line}\033[23m\033[0m\n")


def print_cve_notty(cve: CVE, stream: TextIO):
    stream.write(f"{cve.cve_id}\t{cve.description()}\n")


def hrule(cols: int, stream: TextIO = sys.stdout):
    stream.write("\033[30;1m")
    stream.write("▓" * cols)
    stream.write("\033[0m\n")


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
        for i, cve in enumerate(cves):
            if i == 0:
                hrule(term_size.columns)
            print_cve_tty(cve, sys.stdout, term_size.columns)
            hrule(term_size.columns)
        return

    # expand some CVEs to see if we need to use a pager
    buffer = StringIO()
    pager_proc: Optional[Popen] = None

    for i, cve in enumerate(cves):
        if i == 0:
            hrule(term_size.columns, buffer)
        print_cve_tty(cve, buffer, term_size.columns)
        hrule(term_size.columns, buffer)
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
