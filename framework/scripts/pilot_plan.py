#!/usr/bin/env python3
"""Select a deterministic, control-closed pilot from the frozen full run plan."""

import argparse
import copy
import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path

from common import load_agents, load_json, sha256
from execution_contract import atomic_write_json


ALGORITHM = "deterministic_agent_stratified_greedy_coverage_v1"


def stable_digest(seed, value):
    return hashlib.sha256(f"{seed}|{value}".encode("utf-8")).hexdigest()


def resolve_protocol(experiment_path, experiment, configured=None):
    definition = configured or experiment.get("pilot_protocol", {}).get("definition")
    if not definition:
        raise ValueError("pilot protocol definition is required")
    path = Path(definition)
    if not path.is_absolute():
        path = experiment_path.parent / path
    path = path.resolve()
    protocol = load_json(path)
    if protocol.get("schema_version") != "1.0":
        raise ValueError("pilot protocol schema_version must be 1.0")
    if protocol.get("protocol_id") != "repo-context-pilot-v1":
        raise ValueError("unexpected pilot protocol_id")
    selection = protocol.get("selection", {})
    if selection.get("algorithm") != ALGORITHM:
        raise ValueError(f"pilot selection algorithm must be {ALGORITHM}")
    return path, protocol


def factor_values(experiment):
    design = experiment.get("design", {})
    return {
        "claims": set(design.get("manipulated_claims", [])),
        "locations": set(design.get("locations", [])),
        "methods": set(design.get("methods", [])),
    }


def build_candidates(full_plan, experiment, agent_ids):
    required = factor_values(experiment)
    grouped = defaultdict(list)
    for run in full_plan.get("runs", []):
        if run.get("condition") == "manipulated":
            grouped[run.get("pair_key")].append(run)
    candidates = []
    for pair_key, runs in grouped.items():
        claims = {run.get("claim") for run in runs}
        if claims != required["claims"]:
            raise ValueError(
                f"pilot block {pair_key} does not contain exactly the required claims: "
                f"expected={sorted(required['claims'])} actual={sorted(claims)}"
            )
        agents = {run.get("agent_id") for run in runs}
        projects = {run.get("project_id") for run in runs}
        repeats = {run.get("run") for run in runs}
        if len(agents) != 1 or len(projects) != 1 or len(repeats) != 1:
            raise ValueError(f"pilot block {pair_key} is not project-agent-repeat homogeneous")
        agent = next(iter(agents))
        if agent not in agent_ids:
            raise ValueError(f"unknown agent in pilot block {pair_key}: {agent}")
        candidates.append({
            "pair_key": pair_key,
            "project_id": next(iter(projects)),
            "agent_id": agent,
            "repeat": next(iter(repeats)),
            "runs": runs,
            "claims": claims,
            "locations": {run.get("location") for run in runs},
            "methods": {run.get("method") for run in runs},
            "cells": {(run.get("location"), run.get("method")) for run in runs},
        })
    return candidates


def candidate_score(candidate, covered, selected_projects):
    new_cells = candidate["cells"] - covered["cells"]
    new_locations = candidate["locations"] - covered["locations"]
    new_methods = candidate["methods"] - covered["methods"]
    new_claims = candidate["claims"] - covered["claims"]
    new_project = candidate["project_id"] not in selected_projects
    return (
        len(new_cells) * 1000
        + len(new_locations) * 100
        + len(new_methods) * 100
        + len(new_claims) * 50
        + int(new_project) * 10
    )


def select_blocks(full_plan, experiment, protocol, agent_ids):
    selection = protocol["selection"]
    seed = selection["seed"]
    blocks_per_agent = selection.get("blocks_per_agent")
    if not isinstance(blocks_per_agent, int) or blocks_per_agent < 1:
        raise ValueError("selection.blocks_per_agent must be a positive integer")
    candidates = build_candidates(full_plan, experiment, set(agent_ids))
    by_agent = defaultdict(list)
    for candidate in candidates:
        by_agent[candidate["agent_id"]].append(candidate)
    for agent_id in agent_ids:
        if len(by_agent[agent_id]) < blocks_per_agent:
            raise ValueError(f"not enough candidate blocks for {agent_id}")

    selected = []
    selected_keys = set()
    selected_projects = set()
    covered = {"claims": set(), "locations": set(), "methods": set(), "cells": set()}
    distinct_projects = bool(selection.get("require_distinct_projects"))
    for _slot in range(blocks_per_agent):
        for agent_id in agent_ids:
            pool = [
                candidate for candidate in by_agent[agent_id]
                if candidate["pair_key"] not in selected_keys
                and (not distinct_projects or candidate["project_id"] not in selected_projects)
            ]
            if not pool and distinct_projects:
                raise ValueError(
                    "cannot satisfy distinct-project pilot selection; "
                    "reduce blocks_per_agent or disable the constraint"
                )
            ranked = sorted(
                pool,
                key=lambda candidate: (
                    -candidate_score(candidate, covered, selected_projects),
                    stable_digest(seed, candidate["pair_key"]),
                    candidate["pair_key"],
                ),
            )
            choice = ranked[0]
            selected.append(choice)
            selected_keys.add(choice["pair_key"])
            selected_projects.add(choice["project_id"])
            for field in covered:
                covered[field].update(choice[field])

    required = factor_values(experiment)
    if covered["claims"] != required["claims"]:
        raise ValueError("pilot selection does not cover all manipulated claims")
    if covered["locations"] != required["locations"]:
        raise ValueError("pilot selection does not cover all locations")
    if covered["methods"] != required["methods"]:
        raise ValueError("pilot selection does not cover all methods")
    minimum_cells = selection.get("minimum_location_method_cells", 0)
    if len(covered["cells"]) < minimum_cells:
        raise ValueError(
            f"pilot selection covers {len(covered['cells'])} location-method cells; "
            f"protocol requires {minimum_cells}"
        )
    return selected


def make_pilot_plan(full_plan_path, experiment_path, protocol_path, full_plan,
                    experiment, protocol, selected):
    by_id = {run["run_id"]: run for run in full_plan["runs"]}
    selected_ids = set()
    for block in selected:
        for run in block["runs"]:
            selected_ids.add(run["run_id"])
            if protocol["selection"].get("include_clean_baseline"):
                selected_ids.add(run["baseline_run_id"])
            if protocol["selection"].get("include_location_matched_benign_controls"):
                control_id = run.get("control_run_id")
                if not control_id:
                    raise ValueError(f"manipulated run lacks control_run_id: {run['run_id']}")
                selected_ids.add(control_id)
    missing = sorted(selected_ids - set(by_id))
    if missing:
        raise ValueError(f"pilot references missing full-plan run ids: {missing[:3]}")
    runs = [
        copy.deepcopy(run)
        for run in full_plan["runs"]
        if run["run_id"] in selected_ids
    ]
    condition_counts = Counter(run["condition"] for run in runs)
    manipulated = [run for run in runs if run["condition"] == "manipulated"]
    blocks_per_agent = Counter(block["agent_id"] for block in selected)
    cells = sorted({f"{run['location']}__{run['method']}" for run in manipulated})
    return {
        "schema_version": full_plan.get("schema_version", "4.0"),
        "pilot_schema_version": "1.0",
        "plan_kind": "pilot_subset",
        "pilot_protocol_id": protocol["protocol_id"],
        "experiment_id": experiment["experiment_id"],
        "design_type": full_plan.get("design_type"),
        "benchmark_id": full_plan.get("benchmark_id"),
        "benchmark_manifest": full_plan.get(
            "benchmark_manifest", experiment.get("benchmark_manifest")
        ),
        "context_policy": full_plan.get(
            "context_policy", experiment.get("context_policy")
        ),
        "selection_algorithm": ALGORITHM,
        "source_hashes": {
            "experiment": sha256(experiment_path),
            "full_run_plan": sha256(full_plan_path),
            "pilot_protocol": sha256(protocol_path),
        },
        "selected_block_count": len(selected),
        "run_count": len(runs),
        "condition_counts": {
            condition: condition_counts.get(condition, 0)
            for condition in ("clean", "benign", "manipulated")
        },
        "coverage": {
            "project_ids": sorted({block["project_id"] for block in selected}),
            "agent_ids": sorted({block["agent_id"] for block in selected}),
            "claims": sorted({run["claim"] for run in manipulated}),
            "locations": sorted({run["location"] for run in manipulated}),
            "methods": sorted({run["method"] for run in manipulated}),
            "location_method_cells": cells,
            "blocks_per_agent": dict(sorted(blocks_per_agent.items())),
        },
        "selected_pair_keys": [block["pair_key"] for block in selected],
        "runs": runs,
    }


def main():
    parser = argparse.ArgumentParser(
        description="Select a deterministic, control-closed pilot from a full run plan"
    )
    parser.add_argument("--experiment", required=True)
    parser.add_argument("--full-run-plan", required=True)
    parser.add_argument("--protocol")
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    experiment_path = Path(args.experiment).resolve()
    full_plan_path = Path(args.full_run_plan).resolve()
    experiment = load_json(experiment_path)
    full_plan = load_json(full_plan_path)
    if full_plan.get("experiment_id") != experiment.get("experiment_id"):
        raise SystemExit("full run plan experiment_id mismatch")
    if full_plan.get("schema_version") != "4.0":
        raise SystemExit("full run plan schema_version must be 4.0")
    protocol_path, protocol = resolve_protocol(experiment_path, experiment, args.protocol)
    agent_ids = [agent["agent_id"] for agent in load_agents(experiment_path, experiment)]
    selected = select_blocks(full_plan, experiment, protocol, agent_ids)
    payload = make_pilot_plan(
        full_plan_path, experiment_path, protocol_path,
        full_plan, experiment, protocol, selected,
    )
    atomic_write_json(Path(args.out).resolve(), payload)
    print(json.dumps({
        "selected_blocks": payload["selected_block_count"],
        "run_count": payload["run_count"],
        "condition_counts": payload["condition_counts"],
        "coverage": payload["coverage"],
    }, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
