#!/usr/bin/env python3
import argparse
import json
from pathlib import Path


def print_file(item):
    print(f"  {item.get('filename')} (+{item.get('additions')}/-{item.get('deletions')})")
    patch = item.get("patch")
    if patch:
        for line in patch.splitlines():
            if line.startswith(("+++", "---", "@@", "+", "-")):
                print(f"    {line}")


def main():
    parser = argparse.ArgumentParser(description="Inspect locally saved GitHub commit/compare/PR JSON")
    parser.add_argument("files", nargs="+")
    args = parser.parse_args()

    for arg in args.files:
        path = Path(arg)
        print(f"\n## {path.name}")
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, dict) and "message" in data and "documentation_url" in data:
            print(f"ERROR: {data['message']}")
            continue
        if isinstance(data, list):
            for item in data:
                if "sha" in item and "commit" in item:
                    print(f"  commit {item['sha']} {item['commit']['message'].splitlines()[0]}")
            continue
        if "commit" in data and "files" in data:
            print(f"  commit {data.get('sha')} {data['commit'].get('message', '').splitlines()[0]}")
            for item in data.get("files", []):
                print_file(item)
        elif "files" in data:
            print(
                f"  compare {data.get('status')} ahead={data.get('ahead_by')} "
                f"behind={data.get('behind_by')} commits={data.get('total_commits')}"
            )
            for item in data.get("files", []):
                print_file(item)
        else:
            print(f"  title={data.get('title')} state={data.get('state')} merged={data.get('merged')}")
            print(f"  merge_commit_sha={data.get('merge_commit_sha')}")


if __name__ == "__main__":
    main()
