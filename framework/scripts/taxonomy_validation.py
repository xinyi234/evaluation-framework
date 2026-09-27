#!/usr/bin/env python3
"""Independent codebook coverage and method-semantics review utilities."""
import argparse
import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path

from common import load_benchmark, load_json
from materialize import taxonomy_context


AXES = ("where", "how", "what")
OOC = "OUT_OF_CODEBOOK"


def write_json(path, value):
    Path(path).write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")


def load_rows(path):
    value = load_json(path)
    if not isinstance(value, list):
        raise ValueError(f"{path} must contain a JSON list")
    return value


def validate_corpus(cases, annotations, adjudications, policy, min_heldout):
    errors = []
    case_by_id = {}
    for case in cases:
        required = {"case_id", "source_id", "source_url", "publication_date", "capture_date", "phase", "entry_boundary", "artifact_kind", "evidence_excerpt", "sampling_rationale"}
        if required - set(case):
            errors.append(f"{case.get('case_id')}: missing corpus fields {sorted(required - set(case))}")
            continue
        case_id = case["case_id"]
        if case_id in case_by_id:
            errors.append(f"duplicate case_id: {case_id}")
        if case["phase"] not in ("calibration", "heldout"):
            errors.append(f"{case_id}: phase must be calibration or heldout")
        if not case["source_url"] or not case["evidence_excerpt"] or not case["sampling_rationale"]:
            errors.append(f"{case_id}: source, evidence excerpt, and sampling rationale are required")
        case_by_id[case_id] = case

    source_phases = defaultdict(set)
    for case in case_by_id.values():
        source_phases[case["source_id"]].add(case["phase"])
    for source_id, phases in source_phases.items():
        if len(phases) > 1:
            errors.append(f"source {source_id} appears in both calibration and heldout")

    annotations_by_case = defaultdict(list)
    for row in annotations:
        case_id = row.get("case_id")
        if case_id not in case_by_id:
            errors.append(f"annotation has unknown case_id: {case_id}")
            continue
        if not isinstance(row.get("in_scope"), bool):
            errors.append(f"{case_id}: in_scope must be boolean")
            continue
        if not row.get("coder_id"):
            errors.append(f"{case_id}: coder_id required")
        if row["in_scope"]:
            allowed = {"where": set(policy["locations"]), "how": set(policy["methods"]), "what": set(policy["claim_categories"])}
            for axis in AXES:
                if row.get(axis) not in allowed[axis] | {OOC}:
                    errors.append(f"{case_id}: invalid {axis} label {row.get(axis)}")
            if OOC in [row.get(axis) for axis in AXES] and not row.get("ooc_description"):
                errors.append(f"{case_id}: out-of-codebook label needs a description")
        annotations_by_case[case_id].append(row)

    adjudication_by_case = {row.get("case_id"): row for row in adjudications}
    agreements = Counter()
    heldout = []
    unresolved = []
    for case_id, case in case_by_id.items():
        rows = annotations_by_case[case_id]
        if len(rows) != 2 or len({r.get("coder_id") for r in rows}) != 2:
            errors.append(f"{case_id}: exactly two independent coder annotations required")
            unresolved.append(case_id)
            continue
        same_scope = rows[0]["in_scope"] == rows[1]["in_scope"]
        same_labels = same_scope and (not rows[0]["in_scope"] or all(rows[0].get(axis) == rows[1].get(axis) for axis in AXES))
        agreements["scope_total"] += 1
        agreements["scope_equal"] += int(same_scope)
        if rows[0]["in_scope"] and rows[1]["in_scope"]:
            agreements["labels_total"] += 1
            agreements["labels_equal"] += int(same_labels)
        needs_adjudication = not same_labels or any(OOC in [r.get(axis) for axis in AXES] for r in rows)
        decision = adjudication_by_case.get(case_id)
        if needs_adjudication and decision is None:
            unresolved.append(case_id)
            continue
        final = decision or rows[0]
        if not isinstance(final.get("in_scope"), bool):
            errors.append(f"{case_id}: final in_scope must be boolean")
            continue
        if final["in_scope"]:
            allowed = {"where": set(policy["locations"]), "how": set(policy["methods"]), "what": set(policy["claim_categories"])}
            for axis in AXES:
                if final.get(axis) not in allowed[axis] | {OOC}:
                    errors.append(f"{case_id}: invalid adjudicated {axis}")
        if case["phase"] == "heldout":
            heldout.append((case_id, final))

    in_scope_heldout = [row for _, row in heldout if row["in_scope"]]
    ooc_cases = {axis: [case_id for case_id, row in heldout if row["in_scope"] and row.get(axis) == OOC] for axis in AXES}
    fully_codeable = sum(all(row.get(axis) != OOC for axis in AXES) for row in in_scope_heldout)
    status = "invalid_input" if errors else "pending_annotations" if unresolved or len(in_scope_heldout) < min_heldout else "revision_required" if any(ooc_cases.values()) else "review_ready"
    return {
        "status": status,
        "taxonomy_version": policy["taxonomy_version"],
        "scope": "study_scoped_external_repository_context_cases",
        "case_count": len(cases),
        "heldout_adjudicated_count": len(heldout),
        "heldout_in_scope_count": len(in_scope_heldout),
        "heldout_fully_codeable_count": fully_codeable,
        "heldout_coverage": fully_codeable / len(in_scope_heldout) if in_scope_heldout else None,
        "out_of_codebook_case_ids": ooc_cases,
        "independent_coder_agreement": {
            "scope_exact": agreements["scope_equal"] / agreements["scope_total"] if agreements["scope_total"] else None,
            "labels_exact_when_both_in_scope": agreements["labels_equal"] / agreements["labels_total"] if agreements["labels_total"] else None,
        },
        "unresolved_case_ids": unresolved,
        "errors": errors,
    }


def generate_method_cases(benchmark_path, policy, out, key_out):
    _, projects = load_benchmark(benchmark_path)
    cases, key = [], []
    for card in projects:
        for claim_id in policy["main_levels"]["claims"]:
            for location_id in policy["main_levels"]["locations"]:
                reference = taxonomy_context(card, policy, claim_id, location_id, "M1")["payload_text"]
                for method_id in policy["main_levels"]["methods"]:
                    candidate = taxonomy_context(card, policy, claim_id, location_id, method_id)["payload_text"]
                    raw_id = f"{card['project_id']}|{claim_id}|{location_id}|{method_id}"
                    case_id = hashlib.sha256(raw_id.encode()).hexdigest()[:20]
                    cases.append({"case_id": case_id, "reference_payload": reference, "candidate_payload": candidate,
                                  "review_questions": ["same_security_proposition", "no_extra_security_proposition", "no_agent_directive", "presentation_cue_distinct"]})
                    key.append({"case_id": case_id, "project_id": card["project_id"], "claim": claim_id, "location": location_id, "method": method_id})
    write_json(out, cases)
    write_json(key_out, key)
    return len(cases)


def evaluate_method_cases(key_rows, annotations):
    key = {row["case_id"]: row for row in key_rows}
    by_case = defaultdict(list)
    errors = []
    for row in annotations:
        if row.get("case_id") not in key:
            errors.append(f"unknown case_id: {row.get('case_id')}")
            continue
        if not row.get("coder_id"):
            errors.append(f"{row['case_id']}: coder_id required")
        for field in ("same_security_proposition", "no_extra_security_proposition", "no_agent_directive", "presentation_cue_distinct"):
            if not isinstance(row.get(field), bool):
                errors.append(f"{row['case_id']}: {field} must be boolean")
        by_case[row["case_id"]].append(row)
    if errors:
        return {"status": "invalid_input", "case_count": len(key), "double_coded_count": 0,
                "pending_case_ids": [], "failed_case_ids": [], "disagreement_case_ids": [], "errors": errors}
    pending, failed, disagreements = [], [], []
    for case_id, metadata in key.items():
        rows = by_case[case_id]
        if len(rows) != 2 or len({r.get("coder_id") for r in rows}) != 2:
            pending.append(case_id)
            continue
        fields = ("same_security_proposition", "no_extra_security_proposition", "no_agent_directive", "presentation_cue_distinct")
        if any(rows[0][field] != rows[1][field] for field in fields):
            disagreements.append(case_id)
        if any(not row[field] for row in rows for field in fields if not (field == "presentation_cue_distinct" and metadata["method"] == "M1")):
            failed.append(case_id)
    status = "invalid_input" if errors else "pending_annotations" if pending else "revision_required" if failed or disagreements else "review_ready"
    return {"status": status, "case_count": len(key), "double_coded_count": len(key) - len(pending), "pending_case_ids": pending,
            "failed_case_ids": failed, "disagreement_case_ids": disagreements, "errors": errors}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    corpus = sub.add_parser("evaluate-corpus")
    corpus.add_argument("--policy", required=True)
    corpus.add_argument("--cases", required=True)
    corpus.add_argument("--annotations", required=True)
    corpus.add_argument("--adjudications", required=True)
    corpus.add_argument("--min-heldout", type=int, default=30)
    corpus.add_argument("--out", required=True)
    generate = sub.add_parser("generate-method-cases")
    generate.add_argument("--benchmark", required=True)
    generate.add_argument("--policy", required=True)
    generate.add_argument("--out", required=True)
    generate.add_argument("--key-out", required=True)
    method = sub.add_parser("evaluate-methods")
    method.add_argument("--key", required=True)
    method.add_argument("--annotations", required=True)
    method.add_argument("--out", required=True)
    args = parser.parse_args()
    if args.command == "evaluate-corpus":
        report = validate_corpus(load_rows(args.cases), load_rows(args.annotations), load_rows(args.adjudications), load_json(args.policy), args.min_heldout)
    elif args.command == "generate-method-cases":
        report = {"case_count": generate_method_cases(args.benchmark, load_json(args.policy), args.out, args.key_out)}
    else:
        report = evaluate_method_cases(load_rows(args.key), load_rows(args.annotations))
    if args.command != "generate-method-cases":
        write_json(args.out, report)
    print(json.dumps({key: value for key, value in report.items() if key in ("status", "case_count", "heldout_coverage", "double_coded_count")}, ensure_ascii=False))


if __name__ == "__main__":
    main()
