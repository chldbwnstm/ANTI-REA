"""Ordinary argparse entry point; never executed by ANTI-REA plan/build/staging.

This is the owned caller that is actually integrated around the protected module.
It performs normal CLI parsing, reads a bundled data file and formats output, and
it imports the selected calculation through its normal package-relative name.
"""

import argparse
import sys
from pathlib import Path

from .billing import render_statement


def _footer() -> str:
    note = Path(__file__).with_name("notes.txt")
    return note.read_text(encoding="utf-8").splitlines()[0]


def main(argv=None) -> None:
    parser = argparse.ArgumentParser(prog="ledger_app",
                                     description="Settle a ledger total in integer cents")
    parser.add_argument("--gross-cents", type=int, required=True)
    parser.add_argument("--count", type=int, required=True)
    parser.add_argument("--fee-bps", type=int, default=0)
    args = parser.parse_args(argv)
    try:
        line = render_statement(args.gross_cents, args.count, args.fee_bps)
    except (TypeError, ValueError) as exc:
        print("ledger_app: " + str(exc), file=sys.stderr)
        raise SystemExit(2)
    print(line)
    print(_footer())


if __name__ == "__main__":
    main()
