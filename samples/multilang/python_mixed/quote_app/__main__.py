"""Ordinary application entry point; not executed by ANTI-REA plan/build."""

import argparse

from .pricing import render_quote


def main():
    parser = argparse.ArgumentParser(description="Calculate a quote using integer cents")
    parser.add_argument("--unit-cents", type=int, required=True)
    parser.add_argument("--quantity", type=int, required=True)
    parser.add_argument("--discount-bps", type=int, default=0)
    args = parser.parse_args()
    print(render_quote(args.unit_cents, args.quantity, args.discount_bps))


if __name__ == "__main__":
    main()
