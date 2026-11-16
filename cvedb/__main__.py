"""Console and module entry points with quiet closed-pipe shutdown."""

import os
import sys

from cvedb.cli import main as cli_main


def _flush_stdout() -> bool:
    try:
        sys.stdout.flush()
    except BrokenPipeError:
        with open(os.devnull, "wb") as sink:
            os.dup2(sink.fileno(), sys.stdout.fileno())
        return False
    except KeyboardInterrupt:
        return False
    return True


def main(argv: list[str] | None = None) -> int:
    """Run the CLI and flush output before the interpreter's shutdown phase."""
    try:
        status = cli_main(argv)
    except SystemExit:
        if not _flush_stdout():
            return 1
        raise
    return status if _flush_stdout() else 1


if __name__ == "__main__":
    raise SystemExit(main())
