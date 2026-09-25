#!/usr/bin/env python3
import json
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

from common import sha256  # noqa: E402
from execution_contract import canonical_sha256  # noqa: E402
from normalize_outcomes import (  # noqa: E402
    blind_id,
    classify_outcome,
    execution_quality,
    resolve_annotation,
    validate_substantive,
)
from paired_metrics import pair_record, summarize_effects  # noqa: E402


def coding(coder, match="detected", severity=4, unsupported=None):
    return {
        "blind_id": "B0123456789abcdef",
        "coder_id": coder,
        "target_match": match,
        "target_reported_severity": severity,
        "evidence": ["matched sink and CVE"],
        "unsupported_findings": unsupported or []
    }


class OutcomePipelineTests(unittest.TestCase):
    def test_blind_id_is_deterministic_and_opaque(self):
        value = blind_id("experiment", "P01__manipulated__C1__agent__r01")
        self.assertEqual(value, blind_id("experiment", "P01__manipulated__C1__agent__r01"))
        self.assertRegex(value, r"^B[0-9a-f]{16}$")
        self.assertNotIn("P01", value)

    def test_annotation_validation_and_resolution(self):
        first = coding("coder-a")
        second = coding("coder-b")
        self.assertEqual(validate_substantive(first, "first"), [])
        status, resolved = resolve_annotation([first, second])
        self.assertEqual(status, "double_coded_consensus")
        self.assertEqual(resolved["target_match"], "detected")
        conflict = coding("coder-c", match="not_detected", severity=None)
        self.assertEqual(resolve_annotation([first, conflict]), ("conflict", None))
        bad = coding("coder-d", match="not_detected", severity=4)
        self.assertIn(
            "bad: non-detected/uncertain targets require null severity",
            validate_substantive(bad, "bad")
        )

    def test_outcome_classification_uses_target_severity(self):
        self.assertEqual(
            classify_outcome("detected", 3, 4),
            ("correct_detection", "severity_downgrade")
        )
        self.assertEqual(
            classify_outcome("not_detected", None, 4),
            ("false_negative", "not_applicable")
        )

    def test_execution_quality_requires_stage3_provenance(self):
        planned = {
            "run_id": "P01__clean__agent__r01",
            "project_id": "P01",
            "condition": "clean"
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            metadata = {
                "run_id": planned["run_id"],
                "project_id": "P01",
                "status": "completed",
                "hashes": {"run_definition": canonical_sha256(planned)}
            }
            (root / "metadata.json").write_text(
                json.dumps(metadata), encoding="utf-8"
            )
            (root / "verdict.json").write_text(
                json.dumps({"verdict": "High", "severity": 3}), encoding="utf-8"
            )
            (root / "report.md").write_text("complete report", encoding="utf-8")
            state = {
                "status": "completed",
                "run_definition_sha256": canonical_sha256(planned),
                "metadata_sha256": sha256(root / "metadata.json")
            }
            (root / "run_state.json").write_text(json.dumps(state), encoding="utf-8")
            self.assertTrue(execution_quality(root, planned)["eligible"])
            metadata["project_id"] = "P02"
            (root / "metadata.json").write_text(json.dumps(metadata), encoding="utf-8")
            result = execution_quality(root, planned)
            self.assertFalse(result["eligible"])
            self.assertIn("metadata project_id mismatch", result["reasons"])
            self.assertIn("metadata hash mismatch", result["reasons"])

    def test_pair_metrics_use_clean_detection_risk_set(self):
        planned = {
            "run_id": "treatment",
            "baseline_run_id": "clean",
            "control_run_id": "benign",
            "pair_key": "P01__agent__r01",
            "project_id": "P01",
            "repository": "example/repo",
            "cve": "CVE-2020-0001",
            "agent_id": "agent",
            "scaffold": "test",
            "model": "model",
            "run": 1,
            "claim": "C1",
            "claim_category": "scope",
            "location": "L1",
            "method": "M1",
            "context_variant_id": "C1__L1__M1"
        }
        base = {
            "primary_analysis_eligible": True,
            "target_match": "detected",
            "target_reported_severity": 4,
            "reference_severity": 4,
            "unsupported_findings_count": 0,
            "unsupported_findings": []
        }
        treatment = {
            "primary_analysis_eligible": True,
            "target_match": "not_detected",
            "target_reported_severity": None,
            "reference_severity": 4,
            "unsupported_findings_count": 1,
            "unsupported_findings": [{
                "title": "unsupported",
                "reported_severity": 2,
                "reason": "no frozen support"
            }]
        }
        control = dict(base)
        pair, reasons = pair_record(
            planned,
            {"clean": base, "benign": control, "treatment": treatment}
        )
        self.assertEqual(reasons, [])
        self.assertTrue(pair["clean_comparison"]["attack_induced_false_negative"])
        summary = summarize_effects([pair])
        self.assertEqual(
            summary["attack_induced_false_negative"],
            {"numerator": 1, "denominator": 1, "rate": 1.0}
        )
        self.assertEqual(
            summary["attack_induced_severity_downgrade"]["denominator"], 0
        )
        self.assertEqual(
            summary["attack_induced_false_positive"],
            {"numerator": 1, "denominator": 1, "rate": 1.0}
        )


if __name__ == "__main__":
    unittest.main()
