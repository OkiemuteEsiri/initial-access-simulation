from __future__ import annotations

import json
from pathlib import Path
from .analyzer import Finding, metrics


def validate_remediation(path: str | Path) -> dict:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    required = {"finding_id","owner","change_reference","control_implemented","mfa_enforced","detection_retested","validation_result"}
    if set(data) != required:
        return {"status": "invalid_closure", "missing": sorted(required - set(data))}
    missing = []
    for key in ("finding_id","owner","change_reference"):
        if not isinstance(data[key], str) or not data[key].strip():
            missing.append(key)
    for key in ("control_implemented","mfa_enforced","detection_retested"):
        if data[key] is not True:
            missing.append(key)
    if data["validation_result"] != "pass":
        missing.append("validation_result")
    return {"status": "validated" if not missing else "needs_evidence", "missing": missing}


def render(findings: list[Finding]) -> str:
    m = metrics(findings)
    lines = [
        "# Synthetic Initial Access Assessment",
        "",
        "> Defensive simulation using fictional evidence only. ATT&CK mappings are threat context, not evidence of compromise.",
        "",
        "## Executive summary",
        "",
        f"- Findings: {m['total']}",
        f"- Critical: {m['critical']}",
        f"- High: {m['high']}",
        f"- Maximum contextual score: {m['max_score']}/100",
        "",
        "## Prioritized findings",
        "",
        "| ID | Event | ATT&CK | Score | Severity |",
        "|---|---|---|---:|---|",
    ]
    for f in findings:
        lines.append(f"| {f.finding_id} | {f.event_id} | {f.technique_id} | {f.score} | {f.severity} |")
    lines += ["", "## Analyst rationale", ""]
    for f in findings:
        lines += [f"### {f.finding_id} — {f.technique_name}", "", *[f"- {r}" for r in f.rationale], ""]
    lines += [
        "## Remediation and validation workflow",
        "",
        "1. Confirm accountable owner and approved change reference.",
        "2. Apply preventive controls appropriate to the access path (for example MFA, managed-device policy, or remote-access restriction).",
        "3. Retest detective coverage with benign synthetic events.",
        "4. Record explicit pass/fail evidence before closing the finding.",
        "",
    ]
    return "\n".join(lines)
