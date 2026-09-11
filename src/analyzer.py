from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

ATTACK = {
    "phishing_link": ("T1566.002", "Phishing: Spearphishing Link"),
    "external_remote_service": ("T1133", "External Remote Services"),
    "valid_cloud_account": ("T1078.004", "Valid Accounts: Cloud Accounts"),
    "drive_by": ("T1189", "Drive-by Compromise"),
}

WEIGHTS = {
    "phishing_link": 28,
    "external_remote_service": 32,
    "valid_cloud_account": 34,
    "drive_by": 24,
}

@dataclass(frozen=True)
class Event:
    event_id: str
    technique: str
    asset: str
    asset_criticality: str
    mfa: bool
    managed_device: bool
    successful: bool
    user_privileged: bool
    detection_present: bool

@dataclass(frozen=True)
class Finding:
    finding_id: str
    event_id: str
    score: int
    severity: str
    technique_id: str
    technique_name: str
    rationale: tuple[str, ...]


def _bool(value, field: str) -> bool:
    if type(value) is not bool:
        raise ValueError(f"{field} must be boolean")
    return value


def load_events(path: str | Path) -> list[Event]:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(raw, list):
        raise ValueError("input must be a JSON array")
    seen: set[str] = set()
    events: list[Event] = []
    for row in raw:
        if not isinstance(row, dict):
            raise ValueError("each event must be an object")
        required = {"event_id","technique","asset","asset_criticality","mfa","managed_device","successful","user_privileged","detection_present"}
        if set(row) != required:
            raise ValueError("event fields do not match schema")
        if row["event_id"] in seen:
            raise ValueError("duplicate event_id")
        seen.add(row["event_id"])
        if row["technique"] not in ATTACK:
            raise ValueError("unsupported technique")
        if row["asset_criticality"] not in {"low","medium","high","critical"}:
            raise ValueError("unsupported asset criticality")
        for name in ("event_id","technique","asset","asset_criticality"):
            if not isinstance(row[name], str) or not row[name].strip():
                raise ValueError(f"{name} must be a non-empty string")
        events.append(Event(
            row["event_id"], row["technique"], row["asset"], row["asset_criticality"],
            _bool(row["mfa"], "mfa"), _bool(row["managed_device"], "managed_device"),
            _bool(row["successful"], "successful"), _bool(row["user_privileged"], "user_privileged"),
            _bool(row["detection_present"], "detection_present")
        ))
    return events


def score_event(event: Event) -> tuple[int, tuple[str, ...]]:
    score = WEIGHTS[event.technique]
    reasons = [f"base technique exposure +{score}"]
    mods = [
        (event.successful, 20, "successful access +20"),
        (event.user_privileged, 16, "privileged identity +16"),
        (not event.mfa, 14, "MFA absent +14"),
        (not event.managed_device, 8, "unmanaged device +8"),
        (event.asset_criticality == "critical", 14, "critical asset +14"),
        (event.asset_criticality == "high", 9, "high-criticality asset +9"),
        (event.detection_present, -10, "detective control present -10"),
    ]
    for condition, value, reason in mods:
        if condition:
            score += value
            reasons.append(reason)
    return max(0, min(100, score)), tuple(reasons)


def severity(score: int) -> str:
    if score >= 85: return "critical"
    if score >= 70: return "high"
    if score >= 45: return "medium"
    return "low"


def analyze(events: Iterable[Event]) -> list[Finding]:
    findings = []
    for event in events:
        score, rationale = score_event(event)
        tid, tname = ATTACK[event.technique]
        fid = hashlib.sha256(f"{event.event_id}|{event.asset}|{tid}".encode()).hexdigest()[:12]
        findings.append(Finding(fid, event.event_id, score, severity(score), tid, tname, rationale))
    return sorted(findings, key=lambda f: (-f.score, f.event_id))


def metrics(findings: Iterable[Finding]) -> dict[str, int]:
    fs = list(findings)
    return {
        "total": len(fs),
        "critical": sum(f.severity == "critical" for f in fs),
        "high": sum(f.severity == "high" for f in fs),
        "medium": sum(f.severity == "medium" for f in fs),
        "low": sum(f.severity == "low" for f in fs),
        "max_score": max((f.score for f in fs), default=0),
    }
