#!/usr/bin/env python3
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "trace_extract.py"


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")


class TraceExtractScopeTests(unittest.TestCase):
    def test_run_plan_scope_excludes_unplanned_available_runs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            experiment_path = root / "experiments" / "study.json"
            run_plan_path = root / "pilot.json"
            results = root / "runs"
            output = root / "trace_features.json"
            write_json(root / "benchmark" / "benchmark.json", {
                "project_ids": ["P01"],
                "projects_dir": "projects",
                "project_card_pattern": "{project_id}.json",
            })
            write_json(root / "benchmark" / "projects" / "P01.json", {
                "project_id": "P01",
                "ground_truth": {"vul_files": ["src/vuln.py"], "entry_points": []},
                "context_claim": {"target_areas": ["parser"]},
            })
            write_json(experiment_path, {
                "experiment_id": "test-study",
                "benchmark_manifest": "../benchmark/benchmark.json",
            })
            write_json(run_plan_path, {
                "experiment_id": "test-study",
                "runs": [{"run_id": "selected"}],
            })
            for run_id in ("selected", "unplanned"):
                run_dir = results / run_id
                write_json(run_dir / "metadata.json", {
                    "project_id": "P01",
                    "agent_id": "agent",
                    "scaffold": "test",
                    "model": "model",
                    "condition": "manipulated",
                })
                write_json(run_dir / "context_overlay.json", {
                    "condition": "manipulated",
                    "claim": "C1",
                    "claim_category": "scope",
                    "location": "L1",
                    "method": "M1",
                    "carrier": "SECURITY.md",
                })
                write_json(run_dir / "trace.json", {
                    "source": "stdout_jsonl",
                    "events": [{"path": "SECURITY.md"}, {"path": "src/vuln.py"}],
                })
                (run_dir / "report.md").write_text("The issue remains in scope.", encoding="utf-8")
                write_json(run_dir / "verdict.json", {"justification": "code evidence"})
            completed = subprocess.run(
                [
                    sys.executable, str(SCRIPT),
                    "--results", str(results),
                    "--experiment", str(experiment_path),
                    "--run-plan", str(run_plan_path),
                    "--out", str(output),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(payload["schema_version"], "1.1")
            self.assertEqual(payload["selection_scope"], "run_plan")
            self.assertEqual(payload["requested_run_count"], 1)
            self.assertEqual(payload["run_count"], 1)
            self.assertEqual(payload["missing_run_ids"], [])
            self.assertEqual(set(payload["runs"]), {"selected"})
            self.assertTrue(payload["runs"]["selected"]["features"]["exposure"])


if __name__ == "__main__":
    unittest.main()
