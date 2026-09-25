#!/usr/bin/env python3
import argparse
import json
from collections import Counter
from pathlib import Path

from common import load_agents, load_benchmark, load_json
from design import (
    ALLOCATION_ALGORITHM,
    DESIGN_TYPE,
    SCHEDULE_ALGORITHM,
    assigned_cell,
    schedule_key
)


def relative_path(experiment_path, configured_path):
    experiment_path = Path(experiment_path).resolve()
    experiment_dir = experiment_path.parent
    dataset_root = experiment_dir.parent
    resolved = (experiment_dir / configured_path).resolve()
    return resolved.relative_to(dataset_root).as_posix()


def validate_design_alignment(experiment, policy, agents):
    design = experiment.get("design", {})
    if design.get("type") != DESIGN_TYPE:
        raise ValueError(f"experiment design.type must be {DESIGN_TYPE}")
    if experiment.get("schema_version") != "4.0":
        raise ValueError("experiment schema_version must be 4.0")
    if policy.get("schema_version") != "4.0":
        raise ValueError("context policy schema_version must be 4.0")

    expected = {
        "manipulated_claims": "claims",
        "locations": "locations",
        "methods": "methods"
    }
    for design_key, policy_key in expected.items():
        if design.get(design_key) != policy["main_levels"][policy_key]:
            raise ValueError(
                f"experiment design.{design_key} does not match context-policy main_levels.{policy_key}"
            )

    allocation = design.get("allocation", {})
    if allocation.get("algorithm") != ALLOCATION_ALGORITHM:
        raise ValueError(f"allocation algorithm must be {ALLOCATION_ALGORITHM}")
    if not isinstance(allocation.get("seed"), str) or not allocation["seed"]:
        raise ValueError("allocation seed must be a non-empty string")
    schedule = design.get("execution_schedule", {})
    if schedule.get("algorithm") != SCHEDULE_ALGORITHM:
        raise ValueError(f"execution schedule algorithm must be {SCHEDULE_ALGORITHM}")
    if not isinstance(schedule.get("seed"), str) or not schedule["seed"]:
        raise ValueError("execution schedule seed must be a non-empty string")
    if design.get("benign_locations") != "all":
        raise ValueError("blocked_balanced_v2 requires benign_locations=all")
    if experiment.get("pairing", {}).get("control_location_matched") is not True:
        raise ValueError("blocked_balanced_v2 requires location-matched benign controls")


def base_run(
    card,
    agent_entry,
    agent,
    run,
    experiment,
    workspace_root,
    runs_root
):
    return {
        "project_id": card["project_id"],
        "repository": card["repository"],
        "cve": card["vulnerability"]["cve"],
        "agent_id": agent["agent_id"],
        "scaffold": agent["scaffold"],
        "model": agent["model"],
        "agent_config": agent_entry.get("agent_config"),
        "run": run,
        "timeout_s": agent.get("timeout_s", experiment["budget"]["timeout_s"]),
        "audit_task": experiment["audit_task"],
        "context_policy": experiment["context_policy"],
        "workspace_dir": None,
        "artifact_dir": None,
        "pair_key": f"{card['project_id']}__{agent['agent_id']}__r{run:02d}",
        "baseline_run_id": None,
        "snapshot_archive": card["snapshot"]["archive"]
    }


def add_paths(run, run_id, workspace_root, runs_root):
    run["run_id"] = run_id
    run["workspace_dir"] = f"{workspace_root}/{run_id}/repository"
    run["artifact_dir"] = f"{runs_root}/{run_id}"
    return run


def clean_context_record():
    return {
        "claim": None,
        "claim_category": None,
        "content_mode": None,
        "intended_goal": None,
        "location": None,
        "method": None,
        "carrier": None,
        "carrier_family": None,
        "document_role": None,
        "artifact_format": None,
        "asserted_source": None,
        "method_attributes": None,
        "truthfulness": "not_applicable",
        "factual_status": "not_applicable",
        "rule_authority": "not_applicable",
        "rule_applicability": "not_applicable",
        "evidence_relation": "not_applicable",
        "evidence_reference": None,
        "required_evidence": [],
        "agent_evidence_access": "not_applicable",
        "verifiability": "not_applicable",
        "primary_analysis_eligible": True,
        "context_variant_id": "clean"
    }


def benign_context_record(policy, location_id):
    benign = policy["benign"]
    location = policy["locations"][location_id]
    return {
        "claim": None,
        "claim_category": None,
        "content_mode": benign["content_mode"],
        "intended_goal": None,
        "location": location_id,
        "method": None,
        "carrier": location["carrier"],
        "carrier_family": location["carrier_family"],
        "document_role": location["document_role"],
        "artifact_format": location["artifact_format"],
        "asserted_source": location["asserted_source"],
        "method_attributes": None,
        "truthfulness": benign["truthfulness"],
        "factual_status": benign["factual_status"],
        "rule_authority": benign["rule_authority"],
        "rule_applicability": benign["rule_applicability"],
        "evidence_relation": benign["evidence_relation"],
        "evidence_reference": None,
        "required_evidence": [],
        "agent_evidence_access": benign["agent_evidence_access"],
        "verifiability": benign["verifiability"],
        "primary_analysis_eligible": True,
        "context_variant_id": f"benign__{location_id}"
    }


def manipulated_context_record(policy, claim_id, location_id, method_id):
    claim = policy["claim_categories"][claim_id]
    location = policy["locations"][location_id]
    method = policy["methods"][method_id]
    return {
        "claim": claim_id,
        "claim_category": claim["name"],
        "content_mode": claim["content_mode"],
        "intended_goal": claim["intended_goal"],
        "location": location_id,
        "method": method_id,
        "carrier": location["carrier"],
        "carrier_family": location["carrier_family"],
        "document_role": location["document_role"],
        "artifact_format": location["artifact_format"],
        "asserted_source": location["asserted_source"],
        "method_attributes": method["attributes"],
        "truthfulness": claim["truthfulness"],
        "factual_status": claim["factual_status"],
        "rule_authority": claim["rule_authority"],
        "rule_applicability": claim["rule_applicability"],
        "evidence_relation": claim["evidence_relation"],
        "evidence_reference": claim["evidence_reference"],
        "required_evidence": claim["required_evidence"],
        "agent_evidence_access": claim["agent_evidence_access"],
        "verifiability": claim["verifiability"],
        "primary_analysis_eligible": claim["primary_analysis_eligible"],
        "context_variant_id": f"{claim_id}__{location_id}__{method_id}"
    }


def build_plan(benchmark_path, experiment_path, manifest, projects, experiment, agents):
    experiment_path = Path(experiment_path).resolve()
    policy_path = (experiment_path.parent / experiment["context_policy"]).resolve()
    policy = load_json(policy_path)
    validate_design_alignment(experiment, policy, agents)

    workspace_root = relative_path(experiment_path, experiment["paths"]["workspace_root"])
    runs_root = relative_path(experiment_path, experiment["paths"]["runs_root"])

    claims = experiment["design"]["manipulated_claims"]
    locations = experiment["design"]["locations"]
    methods = experiment["design"]["methods"]
    cell_size = len(locations) * len(methods)
    runs = []

    for project_index, card in enumerate(projects):
        for agent_index, (agent_entry, agent) in enumerate(zip(experiment["agents"], agents)):
            for repeat_index in range(experiment["repeats"]):
                run = repeat_index + 1
                clean_id = f"{card['project_id']}__clean__{agent['agent_id']}__r{run:02d}"
                block_fields = {
                    "project_index": project_index,
                    "agent_index": agent_index,
                    "repeat_index": repeat_index
                }

                clean = base_run(
                    card,
                    agent_entry,
                    agent,
                    run,
                    experiment,
                    workspace_root,
                    runs_root
                )
                clean.update({"condition": "clean", **clean_context_record(), **block_fields})
                add_paths(clean, clean_id, workspace_root, runs_root)
                runs.append(clean)

                benign_ids = {}
                for location_index, location_id in enumerate(locations):
                    benign_id = (
                        f"{card['project_id']}__benign__{location_id}__"
                        f"{agent['agent_id']}__r{run:02d}"
                    )
                    benign = base_run(
                        card,
                        agent_entry,
                        agent,
                        run,
                        experiment,
                        workspace_root,
                        runs_root
                    )
                    benign.update({
                        "condition": "benign",
                        **benign_context_record(policy, location_id),
                        **block_fields,
                        "location_index": location_index,
                        "baseline_run_id": clean_id
                    })
                    add_paths(benign, benign_id, workspace_root, runs_root)
                    runs.append(benign)
                    benign_ids[location_id] = benign_id

                for claim_index, claim_id in enumerate(claims):
                    assignment = assigned_cell(
                        experiment["design"],
                        claim_id,
                        project_index,
                        agent_index,
                        repeat_index,
                        experiment["repeats"]
                    )
                    location_id = assignment["location"]
                    method_id = assignment["method"]
                    location_index = locations.index(location_id)
                    method_index = methods.index(method_id)
                    run_id = (
                        f"{card['project_id']}__manipulated__{claim_id}__{location_id}__"
                        f"{method_id}__{agent['agent_id']}__r{run:02d}"
                    )
                    manipulated = base_run(
                        card,
                        agent_entry,
                        agent,
                        run,
                        experiment,
                        workspace_root,
                        runs_root
                    )
                    manipulated.update({
                        "condition": "manipulated",
                        **manipulated_context_record(policy, claim_id, location_id, method_id),
                        **block_fields,
                        "claim_index": claim_index,
                        "allocation_position": assignment["allocation_position"],
                        "cell_order_hash": assignment["cell_order_hash"],
                        "location_index": location_index,
                        "method_index": method_index,
                        "baseline_run_id": clean_id,
                        "control_run_id": benign_ids[location_id]
                    })
                    add_paths(manipulated, run_id, workspace_root, runs_root)
                    runs.append(manipulated)

    for item in runs:
        item["schedule_key"] = schedule_key(experiment["design"], item["run_id"])
    runs.sort(key=lambda item: item["schedule_key"])
    for schedule_order, item in enumerate(runs, start=1):
        item["schedule_order"] = schedule_order

    condition_counts = Counter(run["condition"] for run in runs)
    expected_count = len(projects) * len(agents) * experiment["repeats"] * (
        1 + len(locations) + len(claims)
    )
    if len(runs) != expected_count:
        raise AssertionError(f"run-plan expansion mismatch: {len(runs)} != {expected_count}")

    return {
        "schema_version": "4.0",
        "experiment_id": experiment["experiment_id"],
        "design_type": experiment["design"]["type"],
        "benchmark_id": manifest["benchmark_id"],
        "benchmark_manifest": experiment["benchmark_manifest"],
        "context_policy": experiment["context_policy"],
        "run_count": len(runs),
        "condition_counts": dict(condition_counts),
        "allocation": {
            "claims": claims,
            "locations": locations,
            "methods": methods,
            "cell_size": cell_size,
            **experiment["design"]["allocation"],
            "benign_locations": locations,
            "execution_schedule": experiment["design"]["execution_schedule"]
        },
        "runs": runs
    }


def main():
    parser = argparse.ArgumentParser(
        description="Expand the balanced S2 repository-context taxonomy run matrix"
    )
    parser.add_argument("--benchmark", required=True)
    parser.add_argument("--experiment", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    manifest, projects = load_benchmark(args.benchmark)
    experiment = load_json(args.experiment)
    agents = load_agents(args.experiment, experiment)
    plan = build_plan(args.benchmark, args.experiment, manifest, projects, experiment, agents)
    Path(args.out).write_text(
        json.dumps(plan, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
        newline="\n"
    )
    print(
        f"run_count={plan['run_count']} "
        f"conditions={json.dumps(plan['condition_counts'])} -> {args.out}"
    )


if __name__ == "__main__":
    main()
