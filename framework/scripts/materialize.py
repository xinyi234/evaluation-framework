#!/usr/bin/env python3
import argparse
import hashlib
import json
import shutil
import zipfile
from pathlib import Path

from common import load_benchmark, load_json, snapshot_path


def safe_extract(zip_path, snapshot_root_dir, destination, force=False):
    destination = Path(destination)
    destination_root = destination.resolve()
    if destination.exists():
        if not force:
            return "cached"
        shutil.rmtree(destination)
    destination.mkdir(parents=True)

    with zipfile.ZipFile(zip_path) as archive:
        prefix = snapshot_root_dir.rstrip("/") + "/"
        for info in archive.infolist():
            name = info.filename.replace("\\", "/")
            if name.endswith("/"):
                continue
            if not name.startswith(prefix):
                raise ValueError(f"zip entry outside expected root: {name}")
            relative = name[len(prefix):]
            target = (destination / relative).resolve()
            if not target.is_relative_to(destination_root):
                raise ValueError(f"unsafe zip target: {target}")
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(info) as source, open(target, "wb") as output:
                shutil.copyfileobj(source, output)
    return "materialized"


def safe_context_path(workspace, carrier):
    workspace = Path(workspace).resolve()
    path = (workspace / carrier).resolve()
    if not path.is_relative_to(workspace):
        raise ValueError(f"unsafe context carrier path: {carrier}")
    return path


def resolve_level(levels, value, level_type):
    if value in levels:
        return value
    names = {specification["name"]: identifier for identifier, specification in levels.items()}
    resolved = names.get(value)
    if resolved is None:
        raise ValueError(f"unknown {level_type}: {value}")
    return resolved


def clean_context():
    return {
        "claim": None,
        "claim_category": None,
        "location": None,
        "method": None,
        "carrier": None,
        "truthfulness": "not_applicable",
        "verifiability": "not_applicable",
        "payload_text": None
    }


def benign_context(policy, location_id):
    locations = policy["locations"]
    location_id = resolve_level(locations, location_id, "location")
    if location_id not in policy["benign"]["templates_by_location"]:
        raise ValueError(f"no benign template for location: {location_id}")
    location = locations[location_id]
    return {
        "claim": None,
        "claim_category": None,
        "location": location_id,
        "method": None,
        "carrier": location["carrier"],
        "truthfulness": policy["benign"]["truthfulness"],
        "verifiability": policy["benign"]["verifiability"],
        "payload_text": policy["benign"]["templates_by_location"][location_id]
    }


def taxonomy_context(card, policy, claim_id, location_id, method_id):
    claims = policy["claim_categories"]
    locations = policy["locations"]
    methods = policy["methods"]

    claim_id = resolve_level(claims, claim_id, "claim category")
    location_id = resolve_level(locations, location_id, "location")
    method_id = resolve_level(methods, method_id, "method")

    claim = claims[claim_id]
    location = locations[location_id]
    method = methods[method_id]
    areas = "\n".join(f"- {area}" for area in card["context_claim"]["target_areas"])
    claim_body = claim["body_template"].format(affected_areas=areas)
    payload_text = method["wrapper_template"].format(
        location_title=location["title"],
        claim_body=claim_body,
        claim_closing=claim["closing"]
    )
    return {
        "claim": claim_id,
        "claim_category": claim["name"],
        "location": location_id,
        "method": method_id,
        "carrier": location["carrier"],
        "truthfulness": claim["truthfulness"],
        "verifiability": claim["verifiability"],
        "payload_text": payload_text
    }


def build_context(card, policy, condition, variant):
    if condition == "clean":
        if variant is not None:
            raise ValueError("clean runs cannot have a context variant")
        return clean_context()
    if condition == "benign":
        if variant is None or variant.get("location") is None:
            raise ValueError("benign runs require a location variant")
        if variant.get("claim") is not None or variant.get("method") is not None:
            raise ValueError("benign runs cannot have a claim or method")
        return benign_context(policy, variant["location"])
    if condition == "manipulated":
        if variant is None:
            raise ValueError("manipulated runs require claim, location, and method")
        missing = [
            key for key in ("claim", "location", "method")
            if variant.get(key) in (None, "")
        ]
        if missing:
            raise ValueError(f"manipulated variant missing fields: {missing}")
        return taxonomy_context(
            card,
            policy,
            variant["claim"],
            variant["location"],
            variant["method"]
        )
    raise ValueError(f"unsupported condition: {condition}")


def materialize_one(
    benchmark_path,
    manifest,
    policy,
    card,
    condition,
    output_root,
    run_id=None,
    force=False,
    variant=None
):
    if policy.get("schema_version") != "4.0":
        raise ValueError("context policy schema_version must be 4.0")

    if run_id:
        workspace = Path(output_root) / run_id / "repository"
    else:
        workspace = Path(output_root) / card["project_id"] / condition

    status = safe_extract(
        snapshot_path(benchmark_path, manifest, card),
        card["snapshot"]["root_directory"],
        workspace,
        force
    )
    context = build_context(card, policy, condition, variant)

    payload_sha256 = None
    if context["payload_text"] is not None:
        carrier_path = safe_context_path(workspace, context["carrier"])
        if carrier_path.exists():
            existing = carrier_path.read_text(encoding="utf-8", errors="strict")
            if status != "cached" or existing != context["payload_text"]:
                raise FileExistsError(
                    f"carrier already exists in upstream snapshot: {carrier_path}"
                )
        else:
            carrier_path.parent.mkdir(parents=True, exist_ok=True)
            carrier_path.write_text(
                context["payload_text"],
                encoding="utf-8",
                newline="\n"
            )
        payload_sha256 = hashlib.sha256(
            context["payload_text"].encode("utf-8")
        ).hexdigest()

    return {
        "run_id": run_id,
        "project_id": card["project_id"],
        "condition": condition,
        "status": status,
        "path": str(workspace),
        "context": {
            "claim": context["claim"],
            "claim_category": context["claim_category"],
            "location": context["location"],
            "method": context["method"],
            "carrier": context["carrier"],
            "truthfulness": context["truthfulness"],
            "verifiability": context["verifiability"],
            "payload_sha256": payload_sha256
        },
        "payload_text": context["payload_text"]
    }


def main():
    parser = argparse.ArgumentParser(
        description="Materialize a pinned repository with a taxonomy context overlay"
    )
    parser.add_argument("--benchmark", required=True)
    parser.add_argument("--experiment", required=True)
    parser.add_argument("--context-policy", required=True)
    parser.add_argument("--project", help="project ID")
    parser.add_argument(
        "--condition",
        choices=["clean", "benign", "manipulated"],
        required=True
    )
    parser.add_argument("--claim", help="claim ID or name, such as C3 or deployment_reachability")
    parser.add_argument("--location", help="location ID or name, such as L5 or deployment_tooling_context")
    parser.add_argument("--method", help="method ID or name, such as M2 or authority_impersonation")
    parser.add_argument("--run-id", help="materialize into workspaces/<run_id>/repository")
    parser.add_argument(
        "--output-root",
        default=str(Path(__file__).resolve().parents[2] / "workspaces"),
        help="workspace root; default is datasets/workspaces"
    )
    parser.add_argument("--force", action="store_true")
    parser.add_argument(
        "--print-payload",
        action="store_true",
        help="print the rendered overlay JSON for review"
    )
    args = parser.parse_args()

    variant = None
    if args.condition == "manipulated":
        if not (args.claim and args.location and args.method):
            raise SystemExit(
                "manipulated materialization requires --claim, --location, and --method"
            )
        variant = {
            "claim": args.claim,
            "location": args.location,
            "method": args.method
        }
    elif args.condition == "benign":
        if not args.location or args.claim or args.method:
            raise SystemExit("benign materialization requires --location only")
        variant = {"claim": None, "location": args.location, "method": None}
    else:
        if args.claim or args.location or args.method:
            raise SystemExit("clean materialization accepts no taxonomy options")

    manifest, projects = load_benchmark(args.benchmark)
    experiment = load_json(args.experiment)
    policy = load_json(args.context_policy)
    if experiment.get("schema_version") != "4.0":
        raise SystemExit("materialize.py requires an S2 schema-v4 experiment")

    if args.project:
        projects = [card for card in projects if card["project_id"] == args.project]
        if not projects:
            raise SystemExit(f"project not found: {args.project}")
    if args.run_id and len(projects) != 1:
        raise SystemExit("--run-id requires exactly one project")

    results = []
    for card in projects:
        result = materialize_one(
            args.benchmark,
            manifest,
            policy,
            card,
            args.condition,
            args.output_root,
            args.run_id,
            args.force,
            variant
        )
        results.append(result)
        identifier = result["run_id"] or f"{result['project_id']}/{result['condition']}"
        print(f"{identifier}: {result['status']} -> {result['path']}")
        if args.print_payload:
            printable = dict(result)
            printable.pop("path", None)
            print(json.dumps(printable, ensure_ascii=False, indent=2))
    print(f"Materialized {len(results)} workspace(s).")


if __name__ == "__main__":
    main()
