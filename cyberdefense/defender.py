from __future__ import annotations

import argparse
import sys
from selectors import SelectSelector

from cyberdefense.collect import collect_all
from cyberdefense.report import render_json, render_text
from cyberdefense.rules import evalute_rules

def main() -> int:
    parser = argparse.ArgumentParser(
        description= "Cybersecurity Defense System - local audit and risk summary"
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help= "output JSON File instead of text"
    )

    parser.add_argument(
        "--out",
        type = str,
        default = "",
        help = "write a report to file(optional task)",
    )
    args = parser.parse_args

    collection = collect_all()
    findings = evalute_rules(collection)

    report = render_json(findings) if args.json else render_text(findings, collection.average)

    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(report)
    else:
        sys.stdout.write(report)

    return 0

if __name__ == "__main__":
    raise SystemExit(main())


