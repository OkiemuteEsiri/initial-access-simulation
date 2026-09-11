from __future__ import annotations

import argparse
from pathlib import Path

from .analyzer import analyze, load_events
from .report import render


def main() -> int:
    parser = argparse.ArgumentParser(description="Analyze synthetic initial-access security events offline")
    parser.add_argument("events", help="Path to synthetic event JSON")
    parser.add_argument("--output", default="reports/generated-assessment.md", help="Markdown report path")
    args = parser.parse_args()

    findings = analyze(load_events(args.events))
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(render(findings), encoding="utf-8")
    print(f"wrote {len(findings)} findings to {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
