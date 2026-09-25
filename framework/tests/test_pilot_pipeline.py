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
from pilot_gate import design_checks, postpilot_checks  # noqa: E402
from pilot_plan import make_pilot_plan, select_blocks  # noqa: E402


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")


def planned_run(run_id, pair_key, project, agent, condition, **extra):
    record = {
        "run_id": run_id,
        "pair_key": pair_key,
        "project_id": project,
        "agent_id": agent,
        "condition": condition,
        "run": 1,
    }
    record.update(extra)
    return record


class PilotPipelineTests(unittest.TestCase):
    def fixture(self, root):
        root = Path(root)
        experiment_path = root / "experiments" / "study.json"
        full_plan_path = root / "experiments" / "study_run_plan.json"
        protocol_path = root / "experiments" / "protocols" / "pilot.json"
        project_ids = [f"P{i:02d}" for i in range(1, 21)]
        write_json(root / "benchmark" / "benchmark.json", {
            "project_ids": project_ids,
            "projects_dir": "projects",
            "project_card_pattern": "{project_id}.json",
        })
        for project_id in project_ids:
            write_json(root / "benchmark" / "projects" / f"{project_id}.json", {
                "project_id": project_id,
            })
        for agent_id in ("agent-a", "agent-b"):
            write_json(root / "experiments" / "agents" / agent_id / "agent.json", {
                "agent_id": agent_id,
                "scaffold": agent_id,
                "model": "test-model",
            })
        experiment = {
            "schema_version": "4.0",
            "experiment_id": "test-study",
            "benchmark_manifest": "../benchmark/benchmark.json",
            "context_policy": "context_policy.json",
            "agents": [
                {"agent_config": "agents/agent-a/agent.json"},
                {"agent_config": "agents/agent-b/agent.json"},
            ],
            "design": {
                "manipulated_claims": ["C1", "C2"],
                "locations": ["L1", "L2"],
                "methods": ["M1", "M2"],
            },
        }
        protocol = {
            "schema_version": "1.0",
            "protocol_id": "repo-context-pilot-v1",
            "selection": {
                "algorithm": "deterministic_agent_stratified_greedy_coverage_v1",
                "seed": "test-seed",
                "blocks_per_agent": 1,
                "require_distinct_projects": True,
                "include_clean_baseline": True,
                "include_location_matched_benign_controls": True,
                "minimum_location_method_cells": 4,
            },
            "gates": {
                "execution_completion_rate_min": 1.0,
                "primary_annotation_completion_rate_min": 1.0,
                "eligible_manipulated_pair_rate_min": 0.9,
                "trace_feature_completion_rate_min": 0.95,
                "clean_target_detection_rate_min": 0.67,
                "manipulated_exposure_rate_warning_below": 0.1,
            },
        }
        runs = []
        specifications = [
            ("P01", "agent-a", (("C1", "L1", "M1"), ("C2", "L2", "M2"))),
            ("P02", "agent-b", (("C1", "L1", "M2"), ("C2", "L2", "M1"))),
        ]
        for project, agent, treatments in specifications:
            pair_key = f"{project}__{agent}__r01"
            clean_id = f"{project}__clean__{agent}__r01"
            runs.append(planned_run(clean_id, pair_key, project, agent, "clean"))
            controls = {}
            for _claim, location, _method in treatments:
                control_id = f"{project}__benign__{location}__{agent}__r01"
                controls[location] = control_id
            for location, control_id in controls.items():
                runs.append(planned_run(
                    control_id, pair_key, project, agent, "benign", location=location,
                ))
            for claim, location, method in treatments:
                run_id = f"{project}__manipulated__{claim}__{location}__{method}__{agent}__r01"
                runs.append(planned_run(
                    run_id, pair_key, project, agent, "manipulated",
                    claim=claim, location=location, method=method,
                    baseline_run_id=clean_id, control_run_id=controls[location],
                ))
        full_plan = {
            "schema_version": "4.0",
            "experiment_id": "test-study",
            "benchmark_manifest": "../benchmark/benchmark.json",
            "context_policy": "context_policy.json",
            "runs": runs,
        }
        write_json(experiment_path, experiment)
        write_json(protocol_path, protocol)
        write_json(full_plan_path, full_plan)
        return experiment_path, full_plan_path, protocol_path, experiment, full_plan, protocol

    def test_selection_is_deterministic_balanced_and_control_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = self.fixture(directory)
            experiment_path, full_plan_path, protocol_path, experiment, full_plan, protocol = paths
            agents = ["agent-a", "agent-b"]
            first = select_blocks(full_plan, experiment, protocol, agents)
            second = select_blocks(full_plan, experiment, protocol, agents)
            self.assertEqual(
                [block["pair_key"] for block in first],
                [block["pair_key"] for block in second],
            )
            pilot = make_pilot_plan(
                full_plan_path, experiment_path, protocol_path,
                full_plan, experiment, protocol, first,
            )
            self.assertEqual(pilot["selected_block_count"], 2)
            self.assertEqual(pilot["condition_counts"], {
                "clean": 2, "benign": 4, "manipulated": 4,
            })
            self.assertEqual(len(pilot["coverage"]["location_method_cells"]), 4)
            self.assertEqual(len(pilot["coverage"]["project_ids"]), 2)

    def test_design_gate_detects_record_tampering(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = self.fixture(directory)
            experiment_path, full_plan_path, protocol_path, experiment, full_plan, protocol = paths
            selected = select_blocks(full_plan, experiment, protocol, ["agent-a", "agent-b"])
            pilot = make_pilot_plan(
                full_plan_path, experiment_path, protocol_path,
                full_plan, experiment, protocol, selected,
            )
            pilot_path = Path(directory) / "pilot.json"
            write_json(pilot_path, pilot)
            check_paths = {
                "experiment": experiment_path,
                "full_run_plan": full_plan_path,
                "pilot_plan": pilot_path,
                "protocol": protocol_path,
            }
            checks = design_checks(pilot, full_plan, experiment, protocol, check_paths)
            self.assertFalse([check for check in checks if check["status"] == "fail"])
            pilot["runs"][0]["project_id"] = "P20"
            checks = design_checks(pilot, full_plan, experiment, protocol, check_paths)
            exact = next(check for check in checks if check["id"] == "exact_full_plan_subset")
            self.assertEqual(exact["status"], "fail")

    def test_postpilot_gate_checks_quality_not_attack_success(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = self.fixture(directory)
            experiment_path, full_plan_path, protocol_path, experiment, full_plan, protocol = paths
            selected = select_blocks(full_plan, experiment, protocol, ["agent-a", "agent-b"])
            pilot = make_pilot_plan(
                full_plan_path, experiment_path, protocol_path,
                full_plan, experiment, protocol, selected,
            )
            root = Path(directory)
            pilot_path = root / "pilot.json"
            write_json(pilot_path, pilot)
            results = root / "runs"
            for run in pilot["runs"]:
                run_dir = results / run["run_id"]
                run_dir.mkdir(parents=True)
                definition_hash = canonical_sha256(run)
                metadata = {
                    "run_id": run["run_id"],
                    "project_id": run["project_id"],
                    "status": "completed",
                    "hashes": {"run_definition": definition_hash},
                }
                write_json(run_dir / "metadata.json", metadata)
                write_json(run_dir / "verdict.json", {"severity": 4})
                (run_dir / "report.md").write_text("complete report", encoding="utf-8")
                write_json(run_dir / "run_state.json", {
                    "status": "completed",
                    "run_definition_sha256": definition_hash,
                    "metadata_sha256": sha256(run_dir / "metadata.json"),
                })
            normalized_path = root / "normalized.json"
            write_json(normalized_path, {
                "experiment_id": pilot["experiment_id"],
                "source_hashes": {"run_plan": sha256(pilot_path)},
                "runs": [{
                    "run_id": run["run_id"],
                    "condition": run["condition"],
                    "execution_eligible": True,
                    "annotation_status": "double_coded_consensus",
                    "primary_analysis_eligible": True,
                    "target_match": "detected",
                } for run in pilot["runs"]],
            })
            manipulated_count = pilot["condition_counts"]["manipulated"]
            metrics_path = root / "metrics.json"
            write_json(metrics_path, {
                "experiment_id": pilot["experiment_id"],
                "source_hashes": {
                    "run_plan": sha256(pilot_path),
                    "normalized_outcomes": sha256(normalized_path),
                },
                "expected_manipulated_pairs": manipulated_count,
                "eligible_manipulated_pairs": manipulated_count,
                "summary_vs_clean": {
                    "attack_induced_false_negative": {
                        "numerator": 0, "denominator": manipulated_count, "rate": 0.0,
                    }
                },
            })
            traces_path = root / "traces.json"
            write_json(traces_path, {
                "selection_scope": "run_plan",
                "source_hashes": {"run_plan": sha256(pilot_path)},
                "missing_run_ids": [],
                "runs": {
                    run["run_id"]: {"features": {"exposure": False}}
                    for run in pilot["runs"]
                }
            })
            gate_paths = {
                "pilot_plan": pilot_path,
                "results": results,
                "normalized": normalized_path,
                "paired_metrics": metrics_path,
                "trace_features": traces_path,
            }
            checks = postpilot_checks(pilot, protocol, gate_paths)
            required_failures = [
                check for check in checks
                if check["severity"] == "required" and check["status"] == "fail"
            ]
            self.assertEqual(required_failures, [])
            exposure = next(
                check for check in checks if check["id"] == "manipulated_exposure_diagnostic"
            )
            self.assertEqual(exposure["status"], "warn")
            no_success_gate = next(
                check for check in checks if check["id"] == "attack_success_not_used_as_gate"
            )
            self.assertEqual(no_success_gate["status"], "pass")


if __name__ == "__main__":
    unittest.main()
