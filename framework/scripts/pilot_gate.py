#!/usr/bin/env python3
"""Evaluate preregistered design and post-pilot quality gates."""

import argparse
import json
from collections import Counter
from pathlib import Path

from common import load_agents, load_benchmark, load_json, sha256
from execution_contract import atomic_write_json, canonical_sha256
from normalize_outcomes import execution_quality
from pilot_plan import factor_values, resolve_protocol


def add_check(checks, check_id, passed, message, severity="required", warn=False):
    status = "pass" if passed else ("warn" if warn or severity == "diagnostic" else "fail")
    checks.append({
        "id": check_id,
        "status": status,
        "severity": severity,
        "message": message,
    })


def design_checks(pilot, full_plan, experiment, protocol, paths):
    checks = []
    add_check(
        checks, "pilot_execution_contract",
        pilot.get("schema_version") == "4.0"
        and pilot.get("pilot_schema_version") == "1.0"
        and pilot.get("plan_kind") == "pilot_subset"
        and pilot.get("benchmark_manifest") == experiment.get("benchmark_manifest")
        and pilot.get("context_policy") == experiment.get("context_policy"),
        "pilot metadata must preserve the run-plan 4.0 execution contract",
    )
    add_check(
        checks, "experiment_identity",
        pilot.get("experiment_id") == experiment.get("experiment_id")
        == full_plan.get("experiment_id"),
        "pilot, full plan, and experiment identifiers must match",
    )
    expected_hashes = {
        "experiment": sha256(paths["experiment"]),
        "full_run_plan": sha256(paths["full_run_plan"]),
        "pilot_protocol": sha256(paths["protocol"]),
    }
    add_check(
        checks, "source_hashes",
        pilot.get("source_hashes") == expected_hashes,
        "pilot source hashes must match the current frozen inputs",
    )

    full_by_id = {run["run_id"]: run for run in full_plan.get("runs", [])}
    pilot_runs = pilot.get("runs", [])
    pilot_ids = [run.get("run_id") for run in pilot_runs]
    exact_subset = len(pilot_ids) == len(set(pilot_ids)) and all(
        run.get("run_id") in full_by_id
        and canonical_sha256(run) == canonical_sha256(full_by_id[run["run_id"]])
        for run in pilot_runs
    )
    add_check(
        checks, "exact_full_plan_subset", exact_subset,
        "every pilot run must be an unchanged, unique record from the full run plan",
    )

    condition_counts = Counter(run.get("condition") for run in pilot_runs)
    counts_match = pilot.get("run_count") == len(pilot_runs) and pilot.get(
        "condition_counts"
    ) == {name: condition_counts.get(name, 0) for name in ("clean", "benign", "manipulated")}
    add_check(checks, "declared_counts", counts_match, "declared pilot counts must equal the run list")

    manipulated = [run for run in pilot_runs if run.get("condition") == "manipulated"]
    selected_pair_keys = set(pilot.get("selected_pair_keys", []))
    actual_pair_keys = {run.get("pair_key") for run in manipulated}
    add_check(
        checks, "selected_blocks",
        pilot.get("selected_block_count") == len(selected_pair_keys)
        and selected_pair_keys == actual_pair_keys,
        "selected block declarations must match manipulated pair keys",
    )

    selected_ids = set(pilot_ids)
    closure_ids = {run["run_id"] for run in manipulated}
    if protocol["selection"].get("include_clean_baseline"):
        closure_ids.update(run.get("baseline_run_id") for run in manipulated)
    if protocol["selection"].get("include_location_matched_benign_controls"):
        closure_ids.update(run.get("control_run_id") for run in manipulated)
    add_check(
        checks, "control_closure",
        None not in closure_ids and closure_ids == selected_ids,
        "pilot must contain exactly its treatments and linked clean/benign controls",
    )

    expected = factor_values(experiment)
    actual = {
        "claims": {run.get("claim") for run in manipulated},
        "locations": {run.get("location") for run in manipulated},
        "methods": {run.get("method") for run in manipulated},
    }
    add_check(
        checks, "factor_coverage",
        actual == expected,
        "pilot must cover every frozen claim, location, and method level",
    )
    cells = {(run.get("location"), run.get("method")) for run in manipulated}
    minimum_cells = protocol["selection"].get("minimum_location_method_cells", 0)
    add_check(
        checks, "location_method_coverage", len(cells) >= minimum_cells,
        f"pilot covers {len(cells)} location-method cells; minimum is {minimum_cells}",
    )

    agents = [agent["agent_id"] for agent in load_agents(paths["experiment"], experiment)]
    blocks_per_agent = Counter()
    pair_agent = {}
    for run in manipulated:
        pair_agent.setdefault(run["pair_key"], run["agent_id"])
    blocks_per_agent.update(pair_agent.values())
    target = protocol["selection"]["blocks_per_agent"]
    add_check(
        checks, "agent_stratification",
        set(blocks_per_agent) == set(agents)
        and all(blocks_per_agent[agent] == target for agent in agents),
        f"each frozen agent must contribute exactly {target} pilot blocks",
    )

    benchmark_path = (paths["experiment"].parent / experiment["benchmark_manifest"]).resolve()
    benchmark, _cards = load_benchmark(benchmark_path)
    full_projects = set(benchmark.get("project_ids", []))
    pilot_projects = {run.get("project_id") for run in pilot_runs}
    add_check(
        checks, "benchmark_project_set_unchanged",
        len(full_projects) == 20 and pilot_projects <= full_projects,
        "the frozen benchmark must retain all 20 projects and the pilot may only sample from them",
    )
    if protocol["selection"].get("require_distinct_projects"):
        add_check(
            checks, "distinct_pilot_projects",
            len(pilot_projects) == pilot.get("selected_block_count"),
            "each selected pilot block must use a distinct project",
        )
    return checks


def postpilot_checks(pilot, protocol, paths):
    checks = []
    runs = pilot["runs"]
    results_root = paths["results"]
    eligible = []
    for run in runs:
        quality = execution_quality(results_root / run["run_id"], run)
        if quality["eligible"]:
            eligible.append(run["run_id"])
    completion_rate = len(eligible) / len(runs) if runs else 0.0
    threshold = protocol["gates"]["execution_completion_rate_min"]
    add_check(
        checks, "execution_completion_rate", completion_rate >= threshold,
        f"execution-eligible {len(eligible)}/{len(runs)} ({completion_rate:.3f}); minimum {threshold:.3f}",
    )

    normalized = load_json(paths["normalized"])
    normalized_runs = normalized.get("runs", [])
    normalized_id_list = [run.get("run_id") for run in normalized_runs]
    normalized_ids = set(normalized_id_list)
    pilot_ids = {run["run_id"] for run in runs}
    add_check(
        checks, "normalized_plan_binding",
        normalized.get("experiment_id") == pilot.get("experiment_id")
        and normalized.get("source_hashes", {}).get("run_plan") == sha256(paths["pilot_plan"])
        and normalized_ids == pilot_ids
        and len(normalized_id_list) == len(normalized_ids),
        "normalized outcomes must be bound to this pilot plan and contain exactly its runs",
    )
    execution_eligible = [run for run in normalized_runs if run.get("execution_eligible")]
    final = [
        run for run in execution_eligible
        if run.get("annotation_status") in {"double_coded_consensus", "adjudicated"}
    ]
    annotation_rate = len(final) / len(execution_eligible) if execution_eligible else 0.0
    threshold = protocol["gates"]["primary_annotation_completion_rate_min"]
    add_check(
        checks, "primary_annotation_completion_rate", annotation_rate >= threshold,
        f"final double-coded/adjudicated outcomes {len(final)}/{len(execution_eligible)} "
        f"({annotation_rate:.3f}); minimum {threshold:.3f}",
    )

    eligible_clean = [
        run for run in normalized_runs
        if run.get("condition") == "clean" and run.get("primary_analysis_eligible")
    ]
    detected_clean = [run for run in eligible_clean if run.get("target_match") == "detected"]
    detection_rate = len(detected_clean) / len(eligible_clean) if eligible_clean else 0.0
    threshold = protocol["gates"]["clean_target_detection_rate_min"]
    add_check(
        checks, "clean_target_detection_rate", detection_rate >= threshold,
        f"clean target detection {len(detected_clean)}/{len(eligible_clean)} "
        f"({detection_rate:.3f}); minimum {threshold:.3f}",
    )

    metrics = load_json(paths["paired_metrics"])
    expected_pairs = sum(run.get("condition") == "manipulated" for run in runs)
    eligible_pairs = metrics.get("eligible_manipulated_pairs", 0)
    pair_rate = eligible_pairs / expected_pairs if expected_pairs else 0.0
    threshold = protocol["gates"]["eligible_manipulated_pair_rate_min"]
    add_check(
        checks, "paired_metrics_binding",
        metrics.get("experiment_id") == pilot.get("experiment_id")
        and metrics.get("source_hashes", {}).get("run_plan") == sha256(paths["pilot_plan"])
        and metrics.get("source_hashes", {}).get("normalized_outcomes")
        == sha256(paths["normalized"]),
        "paired metrics must be hash-bound to this pilot plan and normalized outcome file",
    )
    add_check(
        checks, "eligible_manipulated_pair_rate",
        metrics.get("expected_manipulated_pairs") == expected_pairs and pair_rate >= threshold,
        f"eligible manipulated pairs {eligible_pairs}/{expected_pairs} "
        f"({pair_rate:.3f}); minimum {threshold:.3f}",
    )
    add_check(
        checks, "attack_success_not_used_as_gate", True,
        "observed attack-effect direction or magnitude is not a pilot acceptance criterion",
        severity="diagnostic",
    )

    traces = load_json(paths["trace_features"])
    trace_runs = traces.get("runs", {})
    trace_ids = set(trace_runs)
    add_check(
        checks, "trace_features_binding",
        traces.get("selection_scope") == "run_plan"
        and traces.get("source_hashes", {}).get("run_plan") == sha256(paths["pilot_plan"])
        and traces.get("missing_run_ids") == [],
        "trace screening output must be plan-scoped, hash-bound, and report no missing runs",
    )
    feature_rate = len(trace_ids & pilot_ids) / len(pilot_ids) if pilot_ids else 0.0
    threshold = protocol["gates"]["trace_feature_completion_rate_min"]
    add_check(
        checks, "trace_feature_completion_rate",
        feature_rate >= threshold and not (trace_ids - pilot_ids),
        f"trace feature records {len(trace_ids & pilot_ids)}/{len(pilot_ids)} "
        f"({feature_rate:.3f}); minimum {threshold:.3f}",
    )
    manipulated_ids = {
        run["run_id"] for run in runs if run.get("condition") == "manipulated"
    }
    exposed = sum(
        bool(trace_runs[run_id].get("features", {}).get("exposure"))
        for run_id in manipulated_ids & trace_ids
    )
    exposure_denominator = len(manipulated_ids & trace_ids)
    exposure_rate = exposed / exposure_denominator if exposure_denominator else 0.0
    warning_below = protocol["gates"]["manipulated_exposure_rate_warning_below"]
    add_check(
        checks, "manipulated_exposure_diagnostic", exposure_rate >= warning_below,
        f"automated carrier-exposure screening {exposed}/{exposure_denominator} "
        f"({exposure_rate:.3f}); review instrumentation if below {warning_below:.3f}",
        severity="diagnostic", warn=True,
    )
    return checks


def main():
    parser = argparse.ArgumentParser(description="Evaluate deterministic pilot quality gates")
    parser.add_argument("--phase", required=True, choices=("design", "postpilot"))
    parser.add_argument("--experiment", required=True)
    parser.add_argument("--full-run-plan", required=True)
    parser.add_argument("--pilot-plan", required=True)
    parser.add_argument("--protocol")
    parser.add_argument("--results")
    parser.add_argument("--normalized")
    parser.add_argument("--paired-metrics")
    parser.add_argument("--trace-features")
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    paths = {
        "experiment": Path(args.experiment).resolve(),
        "full_run_plan": Path(args.full_run_plan).resolve(),
        "pilot_plan": Path(args.pilot_plan).resolve(),
    }
    experiment = load_json(paths["experiment"])
    full_plan = load_json(paths["full_run_plan"])
    pilot = load_json(paths["pilot_plan"])
    protocol_path, protocol = resolve_protocol(paths["experiment"], experiment, args.protocol)
    paths["protocol"] = protocol_path
    checks = design_checks(pilot, full_plan, experiment, protocol, paths)

    if args.phase == "postpilot":
        missing_args = [
            name for name in ("results", "normalized", "paired_metrics", "trace_features")
            if getattr(args, name) is None
        ]
        if missing_args:
            raise SystemExit("postpilot phase requires: " + ", ".join(missing_args))
        for name in ("results", "normalized", "paired_metrics", "trace_features"):
            paths[name] = Path(getattr(args, name)).resolve()
        checks.extend(postpilot_checks(pilot, protocol, paths))

    required_failures = [
        check for check in checks
        if check["severity"] == "required" and check["status"] == "fail"
    ]
    if required_failures:
        decision = "hold"
    elif args.phase == "design":
        decision = "ready_for_pilot_execution"
    else:
        decision = "ready_for_main_runs"
    counts = Counter(check["status"] for check in checks)
    source_hashes = {
        "experiment": sha256(paths["experiment"]),
        "full_run_plan": sha256(paths["full_run_plan"]),
        "pilot_plan": sha256(paths["pilot_plan"]),
        "pilot_protocol": sha256(paths["protocol"]),
    }
    for name in ("normalized", "paired_metrics", "trace_features"):
        if name in paths:
            source_hashes[name] = sha256(paths[name])
    payload = {
        "schema_version": "1.0",
        "pilot_protocol_id": protocol["protocol_id"],
        "experiment_id": experiment["experiment_id"],
        "phase": args.phase,
        "decision": decision,
        "source_hashes": source_hashes,
        "summary": {name: counts.get(name, 0) for name in ("pass", "warn", "fail")},
        "checks": checks,
    }
    atomic_write_json(Path(args.out).resolve(), payload)
    print(json.dumps({
        "phase": args.phase,
        "decision": decision,
        "summary": payload["summary"],
    }, ensure_ascii=False, indent=2))
    if decision == "hold":
        raise SystemExit(2)


if __name__ == "__main__":
    main()
