#!/usr/bin/env python3
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

from common import load_benchmark, load_json, sha256, snapshot_path
from materialize import materialize_one
from opencode_trace import harvest as harvest_opencode_session


ALLOWED_PLACEHOLDERS = {
    "{workspace}", "{prompt_file}", "{report}", "{trace}", "{artifact_dir}",
    "{model}", "{agent_config}", "{context_policy}", "{benchmark_manifest}",
    "{run_id}"
}


def safe_remove(path, root):
    path = Path(path).resolve()
    root = Path(root).resolve()
    if not path.is_relative_to(root):
        raise ValueError(f"refusing to remove path outside root: {path}")
    if path.exists():
        shutil.rmtree(path)


def set_nested_json_value(document, dotted_path, value):
    keys = dotted_path.split(".")
    target = document
    for key in keys[:-1]:
        target = target.setdefault(key, {})
    target[keys[-1]] = value


def build_environment(agent, runtime):
    environment = {}
    for name in (
        "PATH", "HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA",
        "SYSTEMROOT", "COMSPEC", "TEMP", "TMP", "LANG", "LC_ALL"
    ):
        if name in os.environ:
            environment[name] = os.environ[name]
    for name in runtime.get("environment_passthrough", []):
        if name in os.environ:
            environment[name] = os.environ[name]
    for injection in agent.get("secret_injections", []):
        name = injection["environment_variable"]
        if name in os.environ:
            environment[name] = os.environ[name]
    return environment


def render_arguments(arguments, values):
    rendered = []
    for argument in arguments:
        try:
            rendered.append(argument.format(**values))
        except (KeyError, IndexError, ValueError) as error:
            raise ValueError(f"invalid placeholder in argument {argument!r}: {error}") from error
    return rendered


def read_stdout_jsonl_events(stdout_path):
    events = []
    with stdout_path.open("r", encoding="utf-8", errors="replace") as source:
        for line in source:
            if not line.strip():
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return events


def parse_stdout_jsonl(stdout_path, trace_path):
    events = []
    errors = []
    with stdout_path.open("r", encoding="utf-8", errors="replace") as source:
        for line_number, line in enumerate(source, start=1):
            if not line.strip():
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError as error:
                errors.append(f"line {line_number}: {error}")
    payload = {"events": events}
    if errors:
        payload["parse_errors"] = errors
    trace_path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
        newline="\n"
    )
    return events


def extract_last_message_text(events):
    """Reconstruct the final assistant report from an opencode-style JSON event
    stream (``opencode run --format json``).

    Provisional extractor: it collects text parts of assistant messages and
    prefers the last block that contains the VERDICT marker.  Validate against
    the first live opencode run before final reporting.
    """
    def assistant_texts():
        for event in events:
            if not isinstance(event, dict):
                continue
            etype = str(event.get("type", ""))
            info = event.get("info")
            if isinstance(info, dict):
                role = info.get("role")
                for part in info.get("parts") or []:
                    if isinstance(part, dict) and part.get("type") == "text" \
                            and isinstance(part.get("text"), str) and role != "user":
                        yield part["text"]
            part = event.get("part")
            # OpenCode 1.17 emits assistant text as standalone events with
            # type="text" and the text payload under event.part.
            if etype == "text" and isinstance(part, dict) \
                    and part.get("type") == "text" and isinstance(part.get("text"), str):
                yield part["text"]
            if etype.startswith("message.part") and isinstance(part, dict) \
                    and part.get("type") == "text" and isinstance(part.get("text"), str):
                yield part["text"]
            if etype.startswith("message") and isinstance(info, dict):
                message = info.get("message")
                for container in (message, info):
                    if isinstance(container, dict) and container.get("role") == "assistant":
                        for part in container.get("parts") or []:
                            if isinstance(part, dict) and part.get("type") == "text" \
                                    and isinstance(part.get("text"), str):
                                yield part["text"]

    texts = list(assistant_texts())
    if not texts:
        return ""
    verdict_texts = [t for t in texts if re.search(r"VERDICT\s*:", t, re.IGNORECASE)]
    if verdict_texts:
        return verdict_texts[-1]
    # Preserve the complete partial transcript when the agent exits without a
    # final report.  Returning only the last reasoning block made report.md
    # appear empty or misleadingly incomplete even though stdout had text.
    return "\n\n".join(t for t in texts if t)


def harvest_session_trace(runtime, values, artifact_dir, trace_path):
    """Harvest a pi session JSONL file (tool calls + messages) into trace.json."""
    template_dir = runtime.get("trace_session_dir")
    if not template_dir:
        trace_path.write_text(
            json.dumps({"events": [], "source": "session_dir", "note": "no trace_session_dir"}, indent=2) + "\n",
            encoding="utf-8", newline="\n")
        return
    session_dir = Path(template_dir.format(**values))
    candidates = list(session_dir.rglob("*.jsonl")) if session_dir.is_dir() else []
    if not candidates:
        trace_path.write_text(
            json.dumps({"events": [], "source": "session_dir", "note": f"no session file under {session_dir}"}, indent=2) + "\n",
            encoding="utf-8", newline="\n")
        return
    chosen = max(candidates, key=lambda c: c.stat().st_mtime)
    raw_dir = artifact_dir / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)
    kept = raw_dir / "pi-session.jsonl"
    shutil.copy2(chosen, kept)
    events = []
    errors = []
    with kept.open("r", encoding="utf-8", errors="replace") as source:
        for line_number, line in enumerate(source, start=1):
            if not line.strip():
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError as error:
                errors.append(f"line {line_number}: {error}")
    payload = {"events": events, "source": "pi-session", "session_file": chosen.name}
    if errors:
        payload["parse_errors"] = errors
    trace_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")


def harvest_opencode_trace(runtime, values, materialization, card, artifact_dir, trace_path):
    """Read this run's opencode session from opencode.db and write a normalized
    trace.json (tool_call / assistant_output / finish with doc_type)."""
    import sys as _sys
    data_home = None
    if runtime.get("xdg_data_home_template"):
        data_home = Path(runtime["xdg_data_home_template"].format(**values))
    try:
        session, events = harvest_opencode_session(
            values["run_id"],
            repo_root=values["workspace"],
            carrier=(materialization.get("context") or {}).get("carrier"),
            ground_truth=(card.get("ground_truth") or {}) if card else None,
            data_home=data_home,
        )
        payload = {"source": "opencode-db", "session_id": session["id"], "events": events}
        status = "ok"
    except (LookupError, FileNotFoundError, RuntimeError) as error:
        payload = {"source": "opencode-db", "events": [], "error": str(error)}
        status = "error"
        print(f"warning: opencode-db trace harvest failed: {error}", file=_sys.stderr)
    trace_path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
        newline="\n"
    )
    return status


def parse_verdict(report_path):
    if not report_path.is_file():
        return {
            "verdict": None,
            "severity": None,
            "justification": None,
            "evidence_files": [],
            "parse_error": "report not found"
        }
    text = report_path.read_text(encoding="utf-8", errors="replace")
    verdict = re.search(r"VERDICT:\s*(Safe|Low|Medium|High|Critical)", text, re.IGNORECASE)
    severity = re.search(r"SEVERITY:\s*([0-4])", text, re.IGNORECASE)
    justification = re.search(
        r"JUSTIFICATION:\s*(.*?)\s*(?:EVIDENCE_FILES:|$)",
        text,
        re.IGNORECASE | re.DOTALL
    )
    evidence_block = re.search(
        r"EVIDENCE_FILES:\s*\r?\n((?:\s*-\s*.*(?:\r?\n)?)+)",
        text,
        re.IGNORECASE
    )
    evidence_files = []
    if evidence_block:
        evidence_files = [
            line.strip().lstrip("-").strip()
            for line in evidence_block.group(1).splitlines()
            if line.strip()
        ]
    if not verdict or not severity:
        return {
            "verdict": verdict.group(1).title() if verdict else None,
            "severity": int(severity.group(1)) if severity else None,
            "justification": justification.group(1).strip() if justification else None,
            "evidence_files": evidence_files,
            "parse_error": "VERDICT or SEVERITY not found"
        }
    return {
        "verdict": verdict.group(1).title(),
        "severity": int(severity.group(1)),
        "justification": justification.group(1).strip() if justification else None,
        "evidence_files": evidence_files
    }


def prepare_workspace_config(agent_path, agent, runtime, workspace, artifact_dir):
    agent_dir = agent_path.parent
    template_path = agent_dir / agent.get("config_template", "")
    if not template_path.is_file():
        return None
    config = load_json(template_path)
    for injection in agent.get("secret_injections", []):
        value = os.environ.get(injection["environment_variable"])
        if value is None:
            raise RuntimeError(
                f"missing environment variable: {injection['environment_variable']}"
            )
        set_nested_json_value(config, injection["destination_json_path"], value)
    workspace_config_name = runtime.get("workspace_config_file")
    if not workspace_config_name:
        raise ValueError("workspace_config_file is required when config_template is set")
    workspace_config_path = workspace / workspace_config_name
    workspace_config_path.write_text(
        json.dumps(config, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
        newline="\n"
    )

    redacted = json.loads(json.dumps(config))
    for injection in agent.get("secret_injections", []):
        set_nested_json_value(redacted, injection["destination_json_path"], "<redacted>")
    return {
        "workspace_config_path": workspace_config_path,
        "redacted_config": redacted
    }


def write_agent_snapshot(agent, runtime, config_info, artifact_dir):
    snapshot = {
        "agent": agent,
        "runtime": runtime
    }
    if config_info:
        snapshot["workspace_config"] = config_info["redacted_config"]
    path = artifact_dir / "agent_config.json"
    path.write_text(
        json.dumps(snapshot, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
        newline="\n"
    )
    return path


def context_variant(run):
    if run["condition"] == "clean":
        return None
    if run["condition"] == "benign":
        return {
            "claim": None,
            "location": run.get("location"),
            "method": None
        }
    if run["condition"] == "manipulated":
        return {
            "claim": run.get("claim"),
            "location": run.get("location"),
            "method": run.get("method")
        }
    raise ValueError(f"unsupported condition: {run['condition']}")


def planned_context(run):
    return {
        "condition": run["condition"],
        "claim": run.get("claim"),
        "claim_category": run.get("claim_category"),
        "location": run.get("location"),
        "method": run.get("method"),
        "carrier": run.get("carrier"),
        "truthfulness": run.get("truthfulness"),
        "verifiability": run.get("verifiability"),
        "context_variant_id": run.get("context_variant_id")
    }


def write_context_overlay(materialization, artifact_dir):
    payload = {
        "condition": materialization["condition"],
        **materialization["context"],
        "payload_text": materialization["payload_text"]
    }
    path = artifact_dir / "context_overlay.json"
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
        newline="\n"
    )
    return path


def execute_run(run, experiment_path, dataset_root, args):
    experiment = load_json(experiment_path)
    if experiment.get("schema_version") != "4.0":
        raise ValueError("run_agent.py requires an S2 schema-v4 experiment")
    benchmark_path = (experiment_path.parent / experiment["benchmark_manifest"]).resolve()
    manifest, projects = load_benchmark(benchmark_path)
    project = next(card for card in projects if card["project_id"] == run["project_id"])
    policy_path = (experiment_path.parent / experiment["context_policy"]).resolve()
    policy = load_json(policy_path)

    workspace = dataset_root / run["workspace_dir"]
    artifact_dir = dataset_root / run["artifact_dir"]
    runs_root = dataset_root / "runs"
    raw_dir = artifact_dir / "raw"

    if args.dry_run:
        return {
            "run_id": run["run_id"],
            "status": "dry-run",
            "context": planned_context(run),
            "workspace": str(workspace),
            "artifact_dir": str(artifact_dir)
        }
    if artifact_dir.exists():
        if not args.force:
            return {"run_id": run["run_id"], "status": "skipped", "reason": "artifact exists"}
        safe_remove(artifact_dir, runs_root)

    snapshot_file = snapshot_path(benchmark_path, manifest, project)
    if sha256(snapshot_file) != run["snapshot_sha256"]:
        raise ValueError(f"snapshot hash mismatch for {run['project_id']}")

    materialization = materialize_one(
        benchmark_path,
        manifest,
        policy,
        project,
        run["condition"],
        dataset_root / "workspaces",
        run["run_id"],
        args.force,
        context_variant(run)
    )
    artifact_dir.mkdir(parents=True, exist_ok=True)
    raw_dir.mkdir(parents=True, exist_ok=True)
    context_overlay_path = write_context_overlay(materialization, artifact_dir)

    prompt_path = artifact_dir / "prompt.txt"
    audit_task_path = (experiment_path.parent / experiment["audit_task"]).resolve()
    prompt = audit_task_path.read_text(encoding="utf-8")
    prompt_path.write_text(prompt, encoding="utf-8", newline="\n")

    agent_path = (experiment_path.parent / run["agent_config"]).resolve()
    agent = load_json(agent_path)
    runtime_path = agent_path.parent / agent["runtime_file"]
    runtime = load_json(runtime_path)
    config_info = prepare_workspace_config(agent_path, agent, runtime, workspace, artifact_dir)
    agent_snapshot_path = write_agent_snapshot(agent, runtime, config_info, artifact_dir)

    report_path = artifact_dir / "report.md"
    trace_path = artifact_dir / "trace.json"
    values = {
        "workspace": str(workspace.resolve()),
        "prompt_file": str(prompt_path.resolve()),
        "report": str(report_path.resolve()),
        "trace": str(trace_path.resolve()),
        "artifact_dir": str(artifact_dir.resolve()),
        "model": agent["model"],
        "agent_config": str(agent_snapshot_path.resolve()),
        "context_policy": str(policy_path.resolve()),
        "benchmark_manifest": str(benchmark_path.resolve()),
        "run_id": run["run_id"]
    }
    arguments = render_arguments(runtime["arguments"], values)
    program = runtime["program"]
    if runtime.get("program_env"):
        program = os.environ.get(runtime["program_env"], program)
    command = [program, *arguments]
    cwd = workspace if runtime["cwd"] == "{workspace}" else artifact_dir
    environment = build_environment(agent, runtime)
    # per-run opencode XDG dirs: isolate config/data so concurrent opencode runs
    # never share/lock the same SQLite db (trace_source = opencode_db).
    xdg_config_template = runtime.get("xdg_config_home_template")
    if xdg_config_template:
        xdg_config = xdg_config_template.format(**values)
        Path(xdg_config).mkdir(parents=True, exist_ok=True)
        environment["XDG_CONFIG_HOME"] = xdg_config
    xdg_data_template = runtime.get("xdg_data_home_template")
    if xdg_data_template:
        xdg_data = xdg_data_template.format(**values)
        Path(xdg_data).mkdir(parents=True, exist_ok=True)
        environment["XDG_DATA_HOME"] = xdg_data

    exit_code = None
    timeout = False
    started_at = datetime.now(timezone.utc).isoformat()
    try:
        completed = subprocess.run(
            command,
            input=prompt if runtime["stdin"] == "prompt" else None,
            cwd=str(cwd),
            env=environment,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=run["timeout_s"]
        )
        exit_code = completed.returncode
        stdout = completed.stdout
        stderr = completed.stderr
    except subprocess.TimeoutExpired as error:
        timeout = True
        exit_code = 124
        stdout = error.stdout or ""
        stderr = error.stderr or ""
        if isinstance(stdout, bytes):
            stdout = stdout.decode("utf-8", errors="replace")
        if isinstance(stderr, bytes):
            stderr = stderr.decode("utf-8", errors="replace")
        stderr += "\n[runner] agent timeout\n"

    stdout_path = artifact_dir / runtime["stdout"]
    stderr_path = artifact_dir / runtime["stderr"]
    stdout_path.parent.mkdir(parents=True, exist_ok=True)
    stderr_path.parent.mkdir(parents=True, exist_ok=True)
    stdout_path.write_text(stdout, encoding="utf-8", newline="\n")
    stderr_path.write_text(stderr, encoding="utf-8", newline="\n")

    # stdout JSONL lines are needed for report reconstruction regardless of the
    # trace source (opencode report is rebuilt from its JSON event stream).
    stdout_lines = None
    if runtime["report_source"] == "jsonl_last_message":
        stdout_lines = read_stdout_jsonl_events(stdout_path)

    if runtime["trace_source"] == "stdout_jsonl":
        parse_stdout_jsonl(stdout_path, trace_path)
    elif runtime["trace_source"] == "session_dir":
        harvest_session_trace(runtime, values, artifact_dir, trace_path)
    elif runtime["trace_source"] == "opencode_db":
        harvest_opencode_trace(runtime, values, materialization, project, artifact_dir, trace_path)
    else:
        trace_path.write_text(
            json.dumps({"events": [], "source": runtime["trace_source"]}, indent=2) + "\n",
            encoding="utf-8",
            newline="\n"
        )

    if runtime["report_source"] == "stdout":
        report_path.write_text(stdout, encoding="utf-8", newline="\n")
    elif runtime["report_source"] == "output_last_message" and not report_path.exists():
        report_path.write_text(stdout, encoding="utf-8", newline="\n")
    elif runtime["report_source"] == "jsonl_last_message":
        if stdout_lines is None:
            stdout_lines = read_stdout_jsonl_events(stdout_path)
        report_text = extract_last_message_text(stdout_lines)
        report_path.write_text(report_text, encoding="utf-8", newline="\n")

    verdict = parse_verdict(report_path)
    (artifact_dir / "verdict.json").write_text(
        json.dumps(verdict, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
        newline="\n"
    )

    metadata = {
        "run_id": run["run_id"],
        "experiment_id": experiment["experiment_id"],
        "project_id": run["project_id"],
        "repository": run["repository"],
        "cve": run["cve"],
        "condition": run["condition"],
        "agent_id": run["agent_id"],
        "scaffold": run["scaffold"],
        "model": run["model"],
        "run": run["run"],
        "pair_key": run["pair_key"],
        "baseline_run_id": run.get("baseline_run_id"),
        "control_run_id": run.get("control_run_id"),
        "context": materialization["context"],
        "context_variant_id": run.get("context_variant_id"),
        "timeout_s": run["timeout_s"],
        "exit_code": exit_code,
        "timeout": timeout,
        "started_at": started_at,
        "finished_at": datetime.now(timezone.utc).isoformat(),
        "workspace": str(workspace),
        "artifact_dir": str(artifact_dir),
        "command": command,
        "benchmark_manifest": str(benchmark_path),
        "context_policy": str(policy_path),
        "audit_task": str(audit_task_path),
        "hashes": {
            "prompt": sha256(prompt_path),
            "agent_config": sha256(agent_snapshot_path),
            "context_policy": sha256(policy_path),
            "context_overlay": sha256(context_overlay_path),
            "benchmark_manifest": sha256(benchmark_path),
            "snapshot_archive": run["snapshot_sha256"]
        }
    }
    (artifact_dir / "metadata.json").write_text(
        json.dumps(metadata, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
        newline="\n"
    )
    return {
        "run_id": run["run_id"],
        "status": (
            "timeout" if timeout else
            "completed" if exit_code == 0 else
            "failed"
        ),
        "exit_code": exit_code,
        "artifact_dir": str(artifact_dir)
    }


def main():
    parser = argparse.ArgumentParser(
        description="Portable agent runner for the balanced S2 taxonomy experiment"
    )
    parser.add_argument("--experiment", required=True)
    parser.add_argument("--run-plan")
    parser.add_argument("--run-id", action="append")
    parser.add_argument("--all", action="store_true")
    parser.add_argument("--agent")
    parser.add_argument("--project")
    parser.add_argument("--condition", choices=["clean", "benign", "manipulated"])
    parser.add_argument("--claim")
    parser.add_argument("--location")
    parser.add_argument("--method")
    parser.add_argument("--repeat", type=int)
    parser.add_argument("--limit", type=int)
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--jobs", type=int, default=1, help="run up to N runs concurrently (default 1 = serial)")
    args = parser.parse_args()

    experiment_path = Path(args.experiment).resolve()
    experiment = load_json(experiment_path)
    plan_path = (
        Path(args.run_plan).resolve()
        if args.run_plan
        else experiment_path.with_name(experiment_path.stem + "_run_plan.json")
    )
    plan = load_json(plan_path)
    if plan.get("schema_version") != "4.0":
        raise SystemExit("run plan schema_version must be 4.0")
    dataset_root = experiment_path.parent.parent

    runs = plan["runs"]
    if args.run_id:
        requested = set(args.run_id)
        runs = [run for run in runs if run["run_id"] in requested]
    if not args.run_id and not args.all:
        raise SystemExit("specify --run-id, or use --all for batch execution")
    if args.agent:
        runs = [run for run in runs if run["agent_id"] == args.agent]
    if args.project:
        runs = [run for run in runs if run["project_id"] == args.project]
    if args.condition:
        runs = [run for run in runs if run["condition"] == args.condition]
    if args.claim:
        runs = [run for run in runs if run.get("claim") == args.claim]
    if args.location:
        runs = [run for run in runs if run.get("location") == args.location]
    if args.method:
        runs = [run for run in runs if run.get("method") == args.method]
    if args.repeat is not None:
        runs = [run for run in runs if run["run"] == args.repeat]
    if args.limit is not None:
        runs = runs[:args.limit]
    if not runs:
        raise SystemExit("no runs selected")

    if args.jobs is None or args.jobs < 1:
        raise SystemExit("--jobs must be >= 1")

    def run_one(run):
        try:
            return execute_run(run, experiment_path, dataset_root, args)
        except Exception as error:
            return {"run_id": run["run_id"], "status": "error", "error": str(error)}

    results = []
    if args.jobs == 1:
        for run in runs:
            result = run_one(run)
            results.append(result)
            print(json.dumps(result, ensure_ascii=False), flush=True)
    else:
        with ThreadPoolExecutor(max_workers=args.jobs) as pool:
            future_to_run = {
                pool.submit(run_one, run): run["run_id"] for run in runs
            }
            for future in as_completed(future_to_run):
                result = future.result()
                results.append(result)
                print(json.dumps(result, ensure_ascii=False), flush=True)

    summary = {
        "selected": len(runs),
        "completed": sum(result["status"] == "completed" for result in results),
        "failed": sum(result["status"] == "failed" for result in results),
        "timeout": sum(result["status"] == "timeout" for result in results),
        "error": sum(result["status"] == "error" for result in results),
        "skipped": sum(result["status"] == "skipped" for result in results),
        "dry_run": sum(result["status"] == "dry-run" for result in results)
    }
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    if any(result["status"] in ("failed", "timeout", "error") for result in results):
        sys.exit(1)


if __name__ == "__main__":
    main()
