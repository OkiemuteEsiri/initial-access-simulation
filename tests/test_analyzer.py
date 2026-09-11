import json
import tempfile
import unittest
from pathlib import Path

from src.analyzer import Event, analyze, load_events, metrics, score_event, severity
from src.report import render, validate_remediation


class AnalyzerTests(unittest.TestCase):
    def event(self, **overrides):
        base = dict(event_id="e1", technique="phishing_link", asset="host1", asset_criticality="high", mfa=False, managed_device=True, successful=True, user_privileged=False, detection_present=True)
        base.update(overrides)
        return Event(**base)

    def test_score_is_bounded(self):
        score, _ = score_event(self.event(user_privileged=True, asset_criticality="critical", managed_device=False, detection_present=False))
        self.assertEqual(score, 100)

    def test_detection_reduces_risk(self):
        a, _ = score_event(self.event(detection_present=True))
        b, _ = score_event(self.event(detection_present=False))
        self.assertLess(a, b)

    def test_mfa_reduces_risk(self):
        a, _ = score_event(self.event(mfa=True))
        b, _ = score_event(self.event(mfa=False))
        self.assertLess(a, b)

    def test_severity_thresholds(self):
        self.assertEqual(severity(85), "critical")
        self.assertEqual(severity(70), "high")
        self.assertEqual(severity(45), "medium")
        self.assertEqual(severity(44), "low")

    def test_findings_are_deterministic(self):
        f1 = analyze([self.event()])[0]
        f2 = analyze([self.event()])[0]
        self.assertEqual(f1.finding_id, f2.finding_id)

    def test_prioritization_descends_by_score(self):
        findings = analyze([self.event(event_id="a", successful=False, mfa=True), self.event(event_id="b", user_privileged=True, detection_present=False)])
        self.assertGreaterEqual(findings[0].score, findings[1].score)

    def test_metrics(self):
        result = metrics(analyze([self.event(), self.event(event_id="e2", successful=False, mfa=True)]))
        self.assertEqual(result["total"], 2)
        self.assertGreaterEqual(result["max_score"], 0)

    def test_report_contains_attack_context(self):
        report = render(analyze([self.event()]))
        self.assertIn("T1566.002", report)
        self.assertIn("Remediation", report)

    def test_duplicate_event_rejected(self):
        rows = [{"event_id":"x","technique":"drive_by","asset":"h","asset_criticality":"low","mfa":True,"managed_device":True,"successful":False,"user_privileged":False,"detection_present":True}]*2
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)/"events.json"; p.write_text(json.dumps(rows))
            with self.assertRaises(ValueError): load_events(p)

    def test_invalid_boolean_rejected(self):
        row = {"event_id":"x","technique":"drive_by","asset":"h","asset_criticality":"low","mfa":"yes","managed_device":True,"successful":False,"user_privileged":False,"detection_present":True}
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)/"events.json"; p.write_text(json.dumps([row]))
            with self.assertRaises(ValueError): load_events(p)

    def test_unknown_technique_rejected(self):
        row = {"event_id":"x","technique":"unknown","asset":"h","asset_criticality":"low","mfa":True,"managed_device":True,"successful":False,"user_privileged":False,"detection_present":True}
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)/"events.json"; p.write_text(json.dumps([row]))
            with self.assertRaises(ValueError): load_events(p)

    def test_remediation_validation(self):
        evidence = {"finding_id":"abc","owner":"IAM","change_reference":"CHG-100","control_implemented":True,"mfa_enforced":True,"detection_retested":True,"validation_result":"pass"}
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)/"evidence.json"; p.write_text(json.dumps(evidence))
            self.assertEqual(validate_remediation(p)["status"], "validated")

    def test_failed_retest_not_closed(self):
        evidence = {"finding_id":"abc","owner":"IAM","change_reference":"CHG-100","control_implemented":True,"mfa_enforced":True,"detection_retested":True,"validation_result":"fail"}
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)/"evidence.json"; p.write_text(json.dumps(evidence))
            self.assertEqual(validate_remediation(p)["status"], "needs_evidence")


if __name__ == "__main__":
    unittest.main()
