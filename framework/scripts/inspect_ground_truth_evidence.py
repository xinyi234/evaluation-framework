#!/usr/bin/env python3
import argparse
import json
import re
from pathlib import Path


RELEVANT_REF = re.compile(
    r"github\.com/.+/(commit|pull)|git[^ ]*commit|/commit/|pull/|"
    r"merge_requests|/patch|/diff|/releases/tag|/issues?/",
    re.IGNORECASE,
)


def load_advisory(path, cve):
    if not path.is_file():
        return None
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None
    if isinstance(value, dict) and value.get("vulnerabilities"):
        return value["vulnerabilities"][0].get("cve")
    if isinstance(value, list):
        return next((item for item in value if item.get("cve_id") == cve), None)
    return value


def print_advisory(record, source_name):
    if not record:
        print(f"  {source_name}: MISSING")
        return
    ghsa_id = record.get("ghsa_id") or record.get("id") or "-"
    summary = (
        record.get("summary")
        or record.get("title")
        or next(
            (item.get("value") for item in record.get("descriptions", []) if item.get("lang") == "en"),
            "-",
        )
    )
    print(f"  {source_name}: {ghsa_id} | {summary}")

    vulnerabilities = record.get("vulnerabilities") or []
    for item in vulnerabilities:
        vulnerable = item.get("vulnerable_version_range") or item.get("version") or "-"
        patched = item.get("first_patched_version") or item.get("fixed_version") or "-"
        package = item.get("package", {}).get("name", "-")
        print(f"    VERSION: {package}: {vulnerable} -> {patched}")

    references = record.get("references") or []
    if isinstance(references, dict):
        references = references.get("url", [])
    for reference in references:
        if isinstance(reference, dict):
            reference = reference.get("url", "")
        if reference and RELEVANT_REF.search(reference):
            print(f"    REF: {reference}")


def main():
    parser = argparse.ArgumentParser(
        description="Print concise GHSA/NVD evidence for benchmark ground-truth review"
    )
    parser.add_argument("--benchmark", required=True)
    parser.add_argument("--evidence-dir", required=True)
    args = parser.parse_args()

    benchmark_path = Path(args.benchmark).resolve()
    evidence_dir = Path(args.evidence_dir).resolve()
    manifest = json.loads(benchmark_path.read_text(encoding="utf-8"))
    for project_id in manifest["project_ids"]:
        card_path = benchmark_path.parent / manifest["projects_dir"] / f"{project_id}.json"
        card = json.loads(card_path.read_text(encoding="utf-8"))
        cve = card["vulnerability"]["cve"]
        print(f"\n## {project_id} | {card['repository']} | {cve}")
        print(f"  SNAPSHOT: {card['snapshot']['archive']}")
        for source_name, filename in (
            ("GHSA", f"ghsa_{cve}.json"),
            ("NVD", f"nvd_{cve}.json"),
        ):
            print_advisory(load_advisory(evidence_dir / filename, cve), source_name)


if __name__ == "__main__":
    main()
