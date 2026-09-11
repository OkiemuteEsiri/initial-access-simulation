# Architecture and Methodology

## Purpose

This project models initial-access security risk from pre-collected synthetic telemetry. It is designed for defensive engineering, control validation, detection coverage review, and recruiter-facing demonstration. It performs no phishing delivery, credential use, scanning, exploitation, or remote access.

## Architecture

```text
synthetic JSON evidence
        |
        v
 strict schema validation
        |
        v
 normalized Event objects
        |
        v
 contextual risk engine -----> MITRE ATT&CK context
        |
        v
 prioritized Finding objects
        |
        +----> Markdown reporting
        |
        +----> remediation evidence validator
```

## Trust boundaries

1. **Evidence boundary** — input is treated as untrusted and rejected on schema/type/duplicate violations.
2. **Scoring boundary** — scores are deterministic, explainable, and bounded to 0–100.
3. **Threat-model boundary** — ATT&CK mappings represent defensive context only; they do not assert that compromise occurred.
4. **Closure boundary** — remediation is not considered validated until evidence records an owner, change reference, implemented control, MFA state, detection retest, and passing result.

## Risk model

The model begins with a technique-specific base exposure score, then applies context modifiers. Higher risk is assigned to successful access, privileged identities, absent MFA, unmanaged devices, and high/critical assets. Confirmed detective coverage reduces the score but never substitutes for preventive controls.

The current mappings are:

| Scenario | MITRE ATT&CK |
|---|---|
| Phishing link | T1566.002 |
| External remote service | T1133 |
| Valid cloud account | T1078.004 |
| Drive-by compromise | T1189 |

## Remediation lifecycle

1. Validate ownership and scope.
2. Select preventive control: MFA, managed-device enforcement, conditional access, remote-service restriction, or equivalent control appropriate to the scenario.
3. Record an approved change reference.
4. Retest detection logic with benign synthetic telemetry.
5. Capture explicit validation outcome.
6. Close only when the evidence validator returns `validated`.

## Limitations

- This is not a penetration-testing framework.
- It does not connect to identity providers, mail systems, endpoints, gateways, or cloud tenants.
- Risk weights are illustrative engineering defaults, not a universal standard.
- ATT&CK technique mappings are contextual and should be adapted to an organization's telemetry and threat model.
