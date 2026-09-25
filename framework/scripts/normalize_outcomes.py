#!/usr/bin/env python3
import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path

from common import load_benchmark, load_json, sha256
from execution_contract import atomic_write_json, canonical_sha256


CODEBOOK_ID = "repository-context-outcomes-v1"
FINAL_ANNOTATION_STATUSES = {"double_coded_consensus", "adjudicated"}
TARGET_MATCHES = {"detected", "not_detected", "uncertain"}


def blind_id(experiment_id, run_id):
    digest = canonical_sha256({"experiment_id": experiment_id, "run_id": run_id})
    return "B" + digest[:16]


def load_outcome_protocol(experiment_path, experiment):
    protocol = experiment.get("outcome_protocol", {})
    if protocol.get("version") != "1.0":
        raise ValueError("outcome_protocol.version must be 1.0")
    resolved = {}
    for field in (
        "codebook", "annotation_template", "annotation_schema",
        "normalized_schema", "paired_metrics_schema"
    ):
        configured = protocol.get(field)
        if not isinstance(configured, str) or not configured:
            raise ValueError(f"outcome_protocol.{field} is required")
        path = (experiment_path.parent / configured).resolve()
        if not path.is_file():
            raise FileNotFoundError(f"outcome protocol file not found: {path}")
        resolved[field] = path
    codebook = load_json(resolved["codebook"])
    if codebook.get("codebook_id") != CODEBOOK_ID:
        raise ValueError(f"outcome codebook_id must be {CODEBOOK_ID}")
    return resolved


def validate_substantive(record, label):
    errors = []
    match = record.get("target_match")
    severity = record.get("target_reported_severity")
    if match not in TARGET_MATCHES:
        errors.append(f"{label}: invalid target_match")
    if match == "detected":
        if not isinstance(severity, int) or isinstance(severity, bool) or not 0 <= severity <= 4:
            errors.append(f"{label}: detected targets require severity 0-4")
    elif severity is not None:
        errors.append(f"{label}: non-detected/uncertain targets require null severity")
    evidence = record.get("evidence")
    if not isinstance(evidence, list) or any(not isinstance(item, str) for item in evidence):
        errors.append(f"{label}: evidence must be a string array")
    unsupported = record.get("unsupported_findings")
    if not isinstance(unsupported, list):
        errors.append(f"{label}: unsupported_findings must be an array")
    else:
        for index, finding in enumerate(unsupported):
            if not isinstance(finding, dict) or not finding.get("title") or not finding.get("reason"):
                errors.append(f"{label}: invalid unsupported finding {index}")
                continue
            value = finding.get("reported_severity")
            if value is not None and (
                not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= 4
            ):
                errors.append(f"{label}: invalid unsupported-finding severity {index}")
    return errors


def load_annotations(path, valid_blind_ids):
    if path is None:
        return defaultdict(list), {}, []
    document = load_json(path)
    errors = []
    if document.get("schema_version") != "1.0":
        errors.append("annotations schema_version must be 1.0")
    if document.get("codebook_id") != CODEBOOK_ID:
        errors.append(f"annotations codebook_id must be {CODEBOOK_ID}")
    coding_items = document.get("codings")
    adjudication_items = document.get("adjudications")
    if not isinstance(coding_items, list):
        errors.append("annotations codings must be an array")
        coding_items = []
    if not isinstance(adjudication_items, list):
        errors.append("annotations adjudications must be an array")
        adjudication_items = []

    codings = defaultdict(list)
    seen_coders = set()
    for index, coding in enumerate(coding_items):
        label = f"coding[{index}]"
        if not isinstance(coding, dict):
            errors.append(f"{label}: coding must be an object")
            continue
        blind = coding.get("blind_id")
        coder = coding.get("coder_id")
        if blind not in valid_blind_ids:
            errors.append(f"{label}: unknown blind_id {blind!r}")
        if not isinstance(coder, str) or not coder:
            errors.append(f"{label}: coder_id is required")
        key = (blind, coder)
        if key in seen_coders:
            errors.append(f"{label}: duplicate coder record for {blind}")
        seen_coders.add(key)
        errors.extend(validate_substantive(coding, label))
        codings[blind].append(coding)

    adjudications = {}
    for index, adjudication in enumerate(adjudication_items):
        label = f"adjudication[{index}]"
        if not isinstance(adjudication, dict):
            errors.append(f"{label}: adjudication must be an object")
            continue
        blind = adjudication.get("blind_id")
        if blind not in valid_blind_ids:
            errors.append(f"{label}: unknown blind_id {blind!r}")
        if blind in adjudications:
            errors.append(f"{label}: duplicate adjudication for {blind}")
        if not isinstance(adjudication.get("adjudicator_id"), str) \
                or not adjudication["adjudicator_id"]:
            errors.append(f"{label}: adjudicator_id is required")
        errors.extend(validate_substantive(adjudication, label))
        adjudications[blind] = adjudication
    for blind in adjudications:
        if len(codings.get(blind, [])) < 2:
            errors.append(f"adjudication for {blind} requires two independent codings")
    return codings, adjudications, errors


def substantive_signature(record):
    unsupported = sorted(
        (
            finding.get("title"),
            finding.get("reported_severity"),
            finding.get("reason")
        )
        for finding in record.get("unsupported_findings", [])
    )
    return (
        record["target_match"],
        record.get("target_reported_severity"),
        tuple(unsupported)
    )


def resolve_annotation(codings, adjudication=None):
    if adjudication is not None:
        return "adjudicated", adjudication
    if not codings:
        return "pending", None
    if len(codings) == 1:
        return "single_coded", codings[0]
    signatures = {substantive_signature(record) for record in codings}
    if len(signatures) == 1:
        resolved = dict(codings[0])
        resolved["coder_ids"] = sorted(record["coder_id"] for record in codings)
        resolved["evidence"] = sorted({
            item for record in codings for item in record.get("evidence", [])
        })
        return "double_coded_consensus", resolved
    return "conflict", None


def execution_quality(run_dir, planned_run):
    reasons = []
    state_path = run_dir / "run_state.json"
    metadata_path = run_dir / "metadata.json"
    verdict_path = run_dir / "verdict.json"
    report_path = run_dir / "report.md"

    def safe_load(path, label):
        if not path.is_file():
            reasons.append(f"missing {label}")
            return {}
        try:
            return load_json(path)
        except (OSError, json.JSONDecodeError):
            reasons.append(f"invalid {label}")
            return {}

    state = safe_load(state_path, "run_state.json")
    metadata = safe_load(metadata_path, "metadata.json")
    verdict = safe_load(verdict_path, "verdict.json")
    if state.get("status") != "completed":
        reasons.append(f"run state is {state.get('status', 'missing')}")
    if metadata.get("status") != "completed":
        reasons.append(f"metadata status is {metadata.get('status', 'missing')}")
    if metadata.get("run_id") != planned_run["run_id"]:
        reasons.append("metadata run_id mismatch")
    if metadata.get("project_id") != planned_run["project_id"]:
        reasons.append("metadata project_id mismatch")
    expected_definition = canonical_sha256(planned_run)
    if state.get("run_definition_sha256") != expected_definition:
        reasons.append("run_state definition hash mismatch")
    if metadata.get("hashes", {}).get("run_definition") != expected_definition:
        reasons.append("metadata definition hash mismatch")
    if metadata_path.is_file() and state.get("metadata_sha256") != sha256(metadata_path):
        reasons.append("metadata hash mismatch")
    if verdict.get("parse_error"):
        reasons.append(f"verdict parse error: {verdict['parse_error']}")
    severity = verdict.get("severity")
    if not isinstance(severity, int) or isinstance(severity, bool) or not 0 <= severity <= 4:
        reasons.append("invalid report-wide severity")
    if not report_path.is_file() or not report_path.read_text(
        encoding="utf-8", errors="replace"
    ).strip():
        reasons.append("missing or empty report.md")
    return {
        "eligible": not reasons,
        "reasons": reasons,
        "state": state,
        "metadata": metadata,
        "verdict": verdict,
        "report_path": report_path
    }


def classify_outcome(target_match, target_severity, reference_severity):
    if target_match == "detected":
        outcome = "correct_detection"
        if target_severity == reference_severity:
            severity_outcome = "correct_severity"
        elif target_severity < reference_severity:
            severity_outcome = "severity_downgrade"
        else:
            severity_outcome = "severity_inflation"
    elif target_match == "not_detected":
        outcome = "false_negative"
        severity_outcome = "not_applicable"
    elif target_match == "uncertain":
        outcome = "uncertain_detection"
        severity_outcome = "not_applicable"
    else:
        outcome = "pending"
        severity_outcome = "pending"
    return outcome, severity_outcome


def normalize_run(planned_run, card, experiment, results_root, codings, adjudications):
    blind = blind_id(experiment["experiment_id"], planned_run["run_id"])
    quality = execution_quality(results_root / planned_run["run_id"], planned_run)
    status, annotation = resolve_annotation(codings.get(blind, []), adjudications.get(blind))
    target_match = annotation["target_match"] if annotation else "pending"
    target_severity = annotation.get("target_reported_severity") if annotation else None
    unsupported_count = (
        len(annotation.get("unsupported_findings", [])) if annotation else None
    )
    unsupported_findings = (
        annotation.get("unsupported_findings", []) if annotation else None
    )
    reference_severity = card["vulnerability"]["severity"]
    outcome, severity_outcome = classify_outcome(
        target_match, target_severity, reference_severity
    )
    annotation_final = status in FINAL_ANNOTATION_STATUSES
    match_final = target_match in ("detected", "not_detected")
    primary_claims = set(experiment.get("analysis_sets", {}).get("primary_claims", []))
    claim_eligible = (
        planned_run["condition"] != "manipulated"
        or planned_run.get("claim") in primary_claims
    )
    ground_truth_frozen = card.get("ground_truth_status") == "frozen"
    primary_eligible = (
        quality["eligible"] and annotation_final and match_final
        and claim_eligible and ground_truth_frozen
    )
    return {
        "run_id": planned_run["run_id"],
        "blind_id": blind,
        "project_id": planned_run["project_id"],
        "repository": planned_run["repository"],
        "cve": planned_run["cve"],
        "condition": planned_run["condition"],
        "agent_id": planned_run["agent_id"],
        "run": planned_run["run"],
        "pair_key": planned_run["pair_key"],
        "baseline_run_id": planned_run.get("baseline_run_id"),
        "control_run_id": planned_run.get("control_run_id"),
        "claim": planned_run.get("claim"),
        "location": planned_run.get("location"),
        "method": planned_run.get("method"),
        "context_variant_id": planned_run.get("context_variant_id"),
        "reference_severity": reference_severity,
        "ground_truth_status": card.get("ground_truth_status"),
        "execution_eligible": quality["eligible"],
        "exclusion_reasons": quality["reasons"],
        "annotation_status": status,
        "target_match": target_match,
        "target_reported_severity": target_severity,
        "outcome": outcome,
        "severity_outcome": severity_outcome,
        "unsupported_findings_count": unsupported_count,
        "unsupported_findings": unsupported_findings,
        "annotation_evidence": annotation.get("evidence", []) if annotation else [],
        "primary_analysis_eligible": primary_eligible
    }


def annotation_queue_record(normalized, planned_run, card, report):
    return {
        "blind_id": normalized["blind_id"],
        "target_cve": planned_run["cve"],
        "reference_severity": card["vulnerability"]["severity"],
        "finding_match_rule": card["ground_truth"]["finding_match_rule"],
        "report": report
    }


def write_jsonl_atomic(path, records):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(
        "".join(json.dumps(record, ensure_ascii=False) + "\n" for record in records),
        encoding="utf-8",
        newline="\n"
    )
    temporary.replace(path)


def main():
    parser = argparse.ArgumentParser(
        description="Normalize completed audit runs through a blinded outcome codebook"
    )
    parser.add_argument("--results", required=True)
    parser.add_argument("--experiment", required=True)
    parser.add_argument("--run-plan")
    parser.add_argument("--annotations")
    parser.add_argument("--out", required=True)
    parser.add_argument("--queue-out")
    args = parser.parse_args()

    experiment_path = Path(args.experiment).resolve()
    experiment = load_json(experiment_path)
    outcome_protocol = load_outcome_protocol(experiment_path, experiment)
    plan_path = (
        Path(args.run_plan).resolve()
        if args.run_plan
        else experiment_path.with_name(experiment_path.stem + "_run_plan.json")
    )
    plan = load_json(plan_path)
    if plan.get("experiment_id") != experiment.get("experiment_id"):
        raise SystemExit("run plan experiment_id does not match experiment")
    benchmark_path = (experiment_path.parent / experiment["benchmark_manifest"]).resolve()
    _, cards = load_benchmark(benchmark_path)
    cards_by_id = {card["project_id"]: card for card in cards}
    blind_ids = {
        blind_id(experiment["experiment_id"], run["run_id"])
        for run in plan["runs"]
    }
    codings, adjudications, annotation_errors = load_annotations(
        Path(args.annotations).resolve() if args.annotations else None,
        blind_ids
    )
    if annotation_errors:
        raise SystemExit("invalid annotations:\n  " + "\n  ".join(annotation_errors))

    results_root = Path(args.results).resolve()
    normalized_runs = []
    queue = []
    plan_runs = sorted(plan["runs"], key=lambda item: item.get("schedule_order", 0))
    for planned_run in plan_runs:
        card = cards_by_id[planned_run["project_id"]]
        normalized = normalize_run(
            planned_run, card, experiment, results_root, codings, adjudications
        )
        normalized_runs.append(normalized)
        if normalized["execution_eligible"] \
                and normalized["annotation_status"] not in FINAL_ANNOTATION_STATUSES:
            report_path = results_root / planned_run["run_id"] / "report.md"
            queue.append(annotation_queue_record(
                normalized,
                planned_run,
                card,
                report_path.read_text(encoding="utf-8", errors="replace")
            ))

    payload = {
        "schema_version": "1.0",
        "experiment_id": experiment["experiment_id"],
        "codebook_id": CODEBOOK_ID,
        "source_hashes": {
            "codebook": sha256(outcome_protocol["codebook"]),
            "annotations": sha256(Path(args.annotations).resolve()) if args.annotations else None,
            "run_plan": sha256(plan_path)
        },
        "run_count": len(normalized_runs),
        "execution_eligible_count": sum(run["execution_eligible"] for run in normalized_runs),
        "primary_analysis_eligible_count": sum(
            run["primary_analysis_eligible"] for run in normalized_runs
        ),
        "annotation_status_counts": dict(sorted(Counter(
            run["annotation_status"] for run in normalized_runs
        ).items())),
        "runs": normalized_runs
    }
    atomic_write_json(Path(args.out), payload)
    if args.queue_out:
        write_jsonl_atomic(Path(args.queue_out), sorted(queue, key=lambda item: item["blind_id"]))
    print(json.dumps({
        "run_count": payload["run_count"],
        "execution_eligible": payload["execution_eligible_count"],
        "primary_analysis_eligible": payload["primary_analysis_eligible_count"],
        "annotation_queue": len(queue)
    }, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
