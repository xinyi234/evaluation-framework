#!/usr/bin/env python3
import argparse
import json
from pathlib import Path

from common import load_benchmark, sha256, snapshot_path


def main():
    parser = argparse.ArgumentParser(description="Create or check the immutable snapshot SHA-256 lock")
    parser.add_argument("--benchmark", required=True)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()

    benchmark_path = Path(args.benchmark).resolve()
    manifest, projects = load_benchmark(benchmark_path)
    lock_path = benchmark_path.parent / manifest["snapshot_lock"]
    snapshots = []
    for card in projects:
        path = snapshot_path(benchmark_path, manifest, card)
        if not path.is_file():
            raise FileNotFoundError(f"{card['project_id']}: snapshot not found: {path}")
        snapshots.append({
            "project_id": card["project_id"],
            "archive": card["snapshot"]["archive"],
            "sha256": sha256(path)
        })

    payload = {
        "schema_version": "1.0",
        "benchmark_id": manifest["benchmark_id"],
        "algorithm": "sha256",
        "snapshots": snapshots
    }
    if args.check:
        if not lock_path.is_file():
            raise SystemExit(f"snapshot lock not found: {lock_path}")
        current = json.loads(lock_path.read_text(encoding="utf-8"))
        if current != payload:
            raise SystemExit("snapshot lock mismatch")
        print(f"Snapshot lock: OK ({len(snapshots)} archives)")
        return

    lock_path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
        newline="\n"
    )
    print(f"Snapshot lock: wrote {len(snapshots)} hashes -> {lock_path}")


if __name__ == "__main__":
    main()
