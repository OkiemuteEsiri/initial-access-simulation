# Initial Access Simulation — Defensive Security Engineering Lab

A recruiter-facing security engineering project for modeling **initial-access risk, control coverage, prioritization, remediation, and validation** from synthetic evidence. The project is intentionally defensive: it does not send phishing messages, use credentials, exploit services, contact production systems, or execute offensive payloads.

## Problem statement

Initial access is often described only as an offensive tactic. Security engineering teams need the opposite view: given evidence that resembles possible phishing, external remote-service exposure, valid-account use, or drive-by activity, how should the organization validate the data, prioritize the risk, map it to threat context, identify missing controls, and prove remediation was effective?

This repository implements that defensive workflow as code.

## Architecture

```text
Synthetic evidence
      |
      v
Schema/type validation
      |
      v
Normalized events
      |
      v
Contextual risk engine
      |
      +----> MITRE ATT&CK mapping
      |
      v
Prioritized findings
      |
      +----> Markdown report
      |
      +----> remediation validation
```

See `docs/architecture-methodology.md` for trust boundaries, scoring methodology, ATT&CK mappings, and closure criteria.

## Repository structure

```text
.
├── .github/workflows/security-quality.yml
├── data/synthetic_events.json
├── docs/architecture-methodology.md
├── src/
│   ├── analyzer.py
│   ├── cli.py
│   └── report.py
└── tests/test_analyzer.py
```

## Defensive scenarios

| Scenario | ATT&CK context | Primary defensive concerns |
|---|---|---|
| Phishing link | T1566.002 | MFA, email/browser controls, endpoint visibility, user reporting |
| External remote service | T1133 | MFA, device trust, remote-access governance, monitoring |
| Valid cloud account | T1078.004 | Conditional access, identity protection, session controls, privilege governance |
| Drive-by compromise | T1189 | Browser hardening, web filtering, endpoint detection, patching |

ATT&CK mappings are used only as defensive threat context. They are not assertions that compromise occurred.

## Risk model

Each finding starts with a scenario-specific base score, then applies contextual modifiers for successful access, privileged identities, missing MFA, unmanaged devices, asset criticality, and detective coverage. Scores are deterministic and bounded to **0–100**.

| Score | Severity |
|---:|---|
| 85–100 | Critical |
| 70–84 | High |
| 45–69 | Medium |
| 0–44 | Low |

The model is intentionally transparent and explainable. It is an engineering prioritization aid, not a universal risk standard.

## Usage

Requires Python 3.12+ and only the standard library.

```bash
python -m src.cli data/synthetic_events.json --output reports/generated-assessment.md
```

The CLI validates input, produces deterministic finding IDs, calculates contextual scores, sorts findings by risk, and writes a Markdown assessment.

## Synthetic dataset

`data/synthetic_events.json` contains fictional events representing different combinations of successful vs unsuccessful access, privileged vs standard identities, MFA state, managed-device state, asset criticality, and detection coverage. No real organization, user, credential, hostname, customer, employer, or production environment is represented.

## Validation philosophy

Input processing is deliberately fail-closed. The loader rejects duplicate event IDs, unsupported scenarios, invalid booleans, unsupported criticality, and missing/extra/malformed fields so ambiguous evidence is not silently scored.

## Remediation workflow

A finding should not be considered closed merely because a control change was proposed. The remediation validator requires evidence of:

1. accountable owner;
2. approved change reference;
3. implemented control;
4. MFA state;
5. detection retest;
6. explicit passing validation result.

Typical defensive actions include conditional-access enforcement, MFA deployment, managed-device requirements, remote-service restrictions, endpoint/browser hardening, and improved monitoring.

## Testing

The unit suite covers score bounds, control modifiers, severity thresholds, deterministic finding IDs, prioritization, metrics, ATT&CK report content, duplicate rejection, strict type validation, unsupported-technique rejection, remediation closure, and failed validation handling.

```bash
python -m unittest discover -s tests -v
```

## CI/CD security checks

The GitHub Actions workflow uses least-privilege permissions (`contents: read`) and performs source/test compilation, unit-test execution, synthetic report generation, and verification that expected ATT&CK mappings appear in output.

A workflow file being present does not by itself prove CI passed; check the Actions result for the relevant commit.

## Design decisions

- **Offline by design:** consumes local synthetic JSON only; no IdP, mail, endpoint, VPN, SIEM, or cloud connection.
- **Deterministic findings:** SHA-256-derived IDs enable reproducible reporting without storing secrets.
- **Explainable prioritization:** every score includes analyst-readable rationale; no opaque ML model.
- **Evidence before closure:** remediation validation requires change and retest evidence rather than status-only closure.

## Limitations

- Synthetic evidence only; no production telemetry ingestion.
- No probabilistic modeling or threat-intelligence enrichment.
- Current scoring weights are illustrative defaults.
- No vendor-specific conditional-access policy parser.
- No SIEM query deployment or active simulation engine.
- ATT&CK mappings should be adapted to local telemetry and threat models.

## Skills demonstrated

**Security Engineering:** control design, trust boundaries, risk prioritization, remediation validation  
**Detection Engineering:** telemetry reasoning, defensive ATT&CK mapping, validation criteria  
**Identity Security:** MFA, privileged-account context, managed-device and cloud-account controls  
**Software Engineering:** Python, immutable models, deterministic processing, unit tests, CLI design  
**DevSecOps:** least-privilege CI, compile/test/report quality gates  
**Risk Communication:** severity model, transparent rationale, remediation workflow

## Roadmap

- Separate identity, endpoint, and network enrichment modules.
- JSON/SARIF output alongside Markdown.
- Control-coverage matrix and compensating-control logic.
- Historical trend comparison for repeated synthetic assessments.
- Policy-as-code examples for conditional access and remote-access baselines.
- Detection coverage assertions for common SIEM schemas.
- Exception expiry and governance evidence.

## Safety and ethics

This repository intentionally excludes credential harvesting, phishing delivery, exploit payloads, scanning, remote authentication, malware, persistence, evasion, and production targeting. It is a defensive security-engineering portfolio project built around synthetic evidence and control validation.
