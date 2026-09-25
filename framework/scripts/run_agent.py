#!/usr/bin/env python3
import argparse
import json
import os
import re
import shutil
import sys
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from common import load_benchmark, load_json, sha256, snapshot_path
from execution_contract import (
    RunLock,
    atomic_write_json,
    canonical_sha256,
    credential_values,
    load_state,
    redact_text,
    resolve_child,
    run_command,
    tree_manifest_sha256,
    utc_now,
    validate_completed_artifacts,
    validate_execution_policy,
    validate_run_id
)
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
    if not path.is_relative_to(root) or path == root:
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
    payload = {"source": "stdout_jsonl", "events": events}
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


def load_execution_policy(experiment_path, experiment):
    configured = experiment.get("execution_policy")
    if not configured:
        raise ValueError("experiment execution_policy is required")
    path = resolve_child(experiment_path.parent, configured, "execution_policy")
    if not path.is_file():
        raise FileNotFoundError(f"execution policy not found: {path}")
    policy = load_json(path)
    errors = validate_execution_policy(policy)
    if errors:
        raise ValueError("invalid execution policy: " + "; ".join(errors))
    return path, policy


def resolve_run_paths(run, experiment, experiment_path, dataset_root):
    validate_run_id(run.get("run_id"))
    workspace_root = (experiment_path.parent / experiment["paths"]["workspace_root"]).resolve()
    runs_root = (experiment_path.parent / experiment["paths"]["runs_root"]).resolve()
    workspace = resolve_child(dataset_root, run["workspace_dir"], "workspace_dir")
    artifact_dir = resolve_child(dataset_root, run["artifact_dir"], "artifact_dir")
    if not workspace.is_relative_to(workspace_root):
        raise ValueError(f"workspace is outside configured workspace root: {workspace}")
    if not artifact_dir.is_relative_to(runs_root):
        raise ValueError(f"artifact directory is outside configured runs root: {artifact_dir}")
    return workspace_root, runs_root, workspace, artifact_dir


def preflight_run(run, experiment_path, dataset_root, require_executable=False):
    experiment = load_json(experiment_path)
    if experiment.get("schema_version") != "4.0":
        raise ValueError("run_agent.py requires an S2 schema-v4 experiment")
    execution_policy_path, execution_policy = load_execution_policy(experiment_path, experiment)
    workspace_root, runs_root, workspace, artifact_dir = resolve_run_paths(
        run, experiment, experiment_path, dataset_root
    )

    agent_path = resolve_child(experiment_path.parent, run["agent_config"], "agent_config")
    if not agent_path.is_file():
        raise FileNotFoundError(f"agent config not found: {agent_path}")
    agent = load_json(agent_path)
    for field in ("agent_id", "scaffold", "model"):
        if run.get(field) != agent.get(field):
            raise ValueError(
                f"stale run plan for {run['run_id']}: {field}={run.get(field)!r} "
                f"but agent config has {agent.get(field)!r}"
            )
    if run.get("timeout_s") != agent.get("timeout_s", experiment["budget"]["timeout_s"]):
        raise ValueError(f"stale run plan timeout for {run['run_id']}")

    runtime_path = resolve_child(agent_path.parent, agent["runtime_file"], "runtime_file")
    if not runtime_path.is_file():
        raise FileNotFoundError(f"runtime config not found: {runtime_path}")
    runtime = load_json(runtime_path)
    if runtime.get("schema_version") != "1.0":
        raise ValueError(f"runtime schema_version must be 1.0: {runtime_path}")
    if not isinstance(runtime.get("arguments"), list) \
            or any(not isinstance(item, str) for item in runtime["arguments"]):
        raise ValueError(f"runtime arguments must be a list of strings: {runtime_path}")
    if runtime.get("stdin") not in ("prompt", "none"):
        raise ValueError(f"unsupported runtime stdin: {runtime.get('stdin')}")
    if runtime.get("cwd") not in ("{workspace}", "{artifact_dir}"):
        raise ValueError(f"unsupported runtime cwd: {runtime.get('cwd')}")
    if runtime.get("trace_source") not in ("none", "stdout_jsonl", "session_dir", "opencode_db"):
        raise ValueError(f"unsupported trace_source: {runtime.get('trace_source')}")
    if runtime.get("report_source") not in (
        "none", "stdout", "output_last_message", "jsonl_last_message"
    ):
        raise ValueError(f"unsupported report_source: {runtime.get('report_source')}")
    for field in ("stdout", "stderr"):
        resolve_child(artifact_dir, runtime[field], f"runtime {field}")
    if runtime.get("workspace_config_file"):
        resolve_child(workspace, runtime["workspace_config_file"], "workspace_config_file")
    isolation_values = {
        "workspace": str(workspace),
        "artifact_dir": str(artifact_dir),
        "run_id": run["run_id"]
    }
    for field in ("xdg_config_home_template", "xdg_data_home_template"):
        template = runtime.get(field)
        if template:
            isolated_path = Path(template.format(**isolation_values)).resolve()
            if not isolated_path.is_relative_to(artifact_dir):
                raise ValueError(f"runtime {field} must resolve inside artifact_dir")
    if runtime.get("trace_session_dir"):
        session_path = Path(runtime["trace_session_dir"].format(**isolation_values)).resolve()
        if not session_path.is_relative_to(workspace) \
                and not session_path.is_relative_to(artifact_dir):
            raise ValueError("runtime trace_session_dir must be isolated per run")

    required_environment = {
        item["environment_variable"]
        for item in agent.get("secret_injections", [])
    }
    required_environment.update(
        name for name in runtime.get("environment_passthrough", [])
        if re.search(r"(?:KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL)$", name, re.IGNORECASE)
    )
    missing_environment = sorted(name for name in required_environment if not os.environ.get(name))
    if require_executable and missing_environment:
        raise RuntimeError(f"missing required environment variables: {missing_environment}")

    program = os.environ.get(runtime.get("program_env", ""), runtime["program"])
    resolved_program = shutil.which(program)
    if require_executable and resolved_program is None:
        raise RuntimeError(f"agent executable not found: {program}")

    return {
        "experiment": experiment,
        "execution_policy_path": execution_policy_path,
        "execution_policy": execution_policy,
        "workspace_root": workspace_root,
        "runs_root": runs_root,
        "workspace": workspace,
        "artifact_dir": artifact_dir,
        "agent_path": agent_path,
        "agent": agent,
        "runtime_path": runtime_path,
        "runtime": runtime,
        "program": resolved_program or program,
        "required_environment": sorted(required_environment)
    }


def remove_workspace_secret_config(preflight):
    runtime = preflight["runtime"]
    configured = runtime.get("workspace_config_file")
    if not configured:
        return
    path = resolve_child(preflight["workspace"], configured, "workspace_config_file")
    try:
        path.unlink()
    except FileNotFoundError:
        pass


def execute_run_locked(run, experiment_path, dataset_root, args, preflight, attempt_id):
    experiment = preflight["experiment"]
    execution_policy = preflight["execution_policy"]
    benchmark_path = (experiment_path.parent / experiment["benchmark_manifest"]).resolve()
    manifest, projects = load_benchmark(benchmark_path)
    project = next(card for card in projects if card["project_id"] == run["project_id"])
    policy_path = (experiment_path.parent / experiment["context_policy"]).resolve()
    policy = load_json(policy_path)
    workspace = preflight["workspace"]
    workspace_root = preflight["workspace_root"]
    artifact_dir = preflight["artifact_dir"]
    runs_root = preflight["runs_root"]
    raw_dir = artifact_dir / "raw"
    state_path = resolve_child(
        artifact_dir,
        execution_policy["artifacts"]["state_file"],
        "state_file"
    )

    if artifact_dir.exists():
        prior_state = load_state(state_path)
        prior_status = prior_state.get("status") if prior_state else None
        if args.force or (args.resume and prior_status != "completed"):
            safe_remove(artifact_dir, runs_root)
        elif prior_status == "completed":
            return {
                "run_id": run["run_id"],
                "status": "skipped",
                "reason": "completed artifact exists"
            }
        else:
            raise RuntimeError(
                "artifact directory is incomplete or has no valid run_state.json; "
                "use --resume to rerun incomplete attempts or --force to rerun any attempt"
            )

    if workspace.exists():
        safe_remove(workspace, workspace_root)
    artifact_dir.mkdir(parents=True, exist_ok=False)
    raw_dir.mkdir(parents=True, exist_ok=True)
    started_at = utc_now()
    started_clock = time.monotonic()
    atomic_write_json(state_path, {
        "schema_version": "1.0",
        "run_id": run["run_id"],
        "attempt_id": attempt_id,
        "status": "running",
        "started_at": started_at,
        "run_definition_sha256": canonical_sha256(run)
    })

    snapshot_file = snapshot_path(benchmark_path, manifest, project)
    snapshot_sha256 = sha256(snapshot_file)
    expected_snapshot_sha256 = run.get("snapshot_sha256")
    if expected_snapshot_sha256 and snapshot_sha256 != expected_snapshot_sha256:
        raise ValueError(f"snapshot hash mismatch for {run['project_id']}")

    materialization = materialize_one(
        benchmark_path,
        manifest,
        policy,
        project,
        run["condition"],
        workspace_root,
        run["run_id"],
        False,
        context_variant(run)
    )
    context_overlay_path = write_context_overlay(materialization, artifact_dir)

    prompt_path = artifact_dir / "prompt.txt"
    audit_task_path = (experiment_path.parent / experiment["audit_task"]).resolve()
    prompt = audit_task_path.read_text(encoding="utf-8")
    prompt_path.write_text(prompt, encoding="utf-8", newline="\n")

    agent_path = preflight["agent_path"]
    agent = preflight["agent"]
    runtime_path = preflight["runtime_path"]
    runtime = preflight["runtime"]
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
    program = preflight["program"]
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

    workspace_exclusions = []
    if runtime.get("workspace_config_file"):
        workspace_exclusions.append(runtime["workspace_config_file"])
    if runtime.get("trace_session_dir"):
        session_path = Path(runtime["trace_session_dir"].format(**values)).resolve()
        if session_path.is_relative_to(workspace):
            workspace_exclusions.append(session_path.relative_to(workspace).as_posix())
    workspace_sha256_before = tree_manifest_sha256(workspace, workspace_exclusions)

    exit_code, stdout, stderr, timeout = run_command(
        command,
        prompt if runtime["stdin"] == "prompt" else None,
        cwd,
        environment,
        run["timeout_s"]
    )

    secrets = credential_values(agent, runtime)
    stdout = redact_text(stdout, secrets)
    stderr = redact_text(stderr, secrets)

    stdout_path = resolve_child(artifact_dir, runtime["stdout"], "runtime stdout")
    stderr_path = resolve_child(artifact_dir, runtime["stderr"], "runtime stderr")
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

    for sensitive_output in (report_path, trace_path):
        if sensitive_output.is_file():
            text = sensitive_output.read_text(encoding="utf-8", errors="replace")
            sensitive_output.write_text(
                redact_text(text, secrets),
                encoding="utf-8",
                newline="\n"
            )

    verdict = parse_verdict(report_path)
    atomic_write_json(artifact_dir / "verdict.json", verdict)
    workspace_sha256_after = tree_manifest_sha256(workspace, workspace_exclusions)

    project_card_path = (
        benchmark_path.parent
        / manifest["projects_dir"]
        / manifest.get("project_card_pattern", "{project_id}.json").format(
            project_id=run["project_id"]
        )
    ).resolve()
    input_hashes = {
        "run_definition": canonical_sha256(run),
        "snapshot_archive": snapshot_sha256,
        "audit_task": sha256(audit_task_path),
        "agent_config_source": sha256(agent_path),
        "runtime_config_source": sha256(runtime_path),
        "execution_policy": sha256(preflight["execution_policy_path"]),
        "context_policy": sha256(policy_path),
        "benchmark_manifest": sha256(benchmark_path),
        "project_card": sha256(project_card_path),
        "prompt": sha256(prompt_path),
        "agent_config_snapshot": sha256(agent_snapshot_path),
        "context_overlay": sha256(context_overlay_path)
    }
    redacted_command = [redact_text(str(item), secrets) for item in command]

    metadata = {
        "schema_version": "1.0",
        "run_id": run["run_id"],
        "attempt_id": attempt_id,
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
        "finished_at": utc_now(),
        "duration_s": round(time.monotonic() - started_clock, 6),
        "workspace": str(workspace),
        "artifact_dir": str(artifact_dir),
        "command": redacted_command,
        "environment_variable_names": sorted(environment),
        "workspace_integrity": {
            "excluded_paths": sorted(workspace_exclusions),
            "before_sha256": workspace_sha256_before,
            "after_sha256": workspace_sha256_after,
            "unchanged": workspace_sha256_before == workspace_sha256_after
        },
        "benchmark_manifest": str(benchmark_path),
        "context_policy": str(policy_path),
        "audit_task": str(audit_task_path),
        "hashes": input_hashes
    }
    metadata_path = artifact_dir / "metadata.json"
    atomic_write_json(metadata_path, metadata)
    artifact_errors = validate_completed_artifacts(
        artifact_dir, runtime, verdict, execution_policy
    )
    if workspace_sha256_before != workspace_sha256_after:
        artifact_errors.append("workspace changed during the agent audit")
    status = (
        "timeout" if timeout else
        "failed" if exit_code != 0 else
        "incomplete" if artifact_errors else
        "completed"
    )
    metadata["status"] = status
    metadata["artifact_errors"] = artifact_errors
    atomic_write_json(metadata_path, metadata)
    finished_at = utc_now()
    atomic_write_json(state_path, {
        "schema_version": "1.0",
        "run_id": run["run_id"],
        "attempt_id": attempt_id,
        "status": status,
        "started_at": started_at,
        "finished_at": finished_at,
        "exit_code": exit_code,
        "timeout": timeout,
        "artifact_errors": artifact_errors,
        "run_definition_sha256": input_hashes["run_definition"],
        "metadata_sha256": sha256(metadata_path)
    })
    return {
        "run_id": run["run_id"],
        "status": status,
        "exit_code": exit_code,
        "artifact_errors": artifact_errors,
        "artifact_dir": str(artifact_dir)
    }


def execute_run(run, experiment_path, dataset_root, args):
    preflight = preflight_run(
        run,
        experiment_path,
        dataset_root,
        require_executable=not args.dry_run
    )
    if args.dry_run:
        return {
            "run_id": run["run_id"],
            "status": "dry-run",
            "context": planned_context(run),
            "workspace": str(preflight["workspace"]),
            "artifact_dir": str(preflight["artifact_dir"]),
            "execution_policy": str(preflight["execution_policy_path"])
        }

    attempt_id = str(uuid.uuid4())
    lock_root = preflight["runs_root"] / ".locks"
    try:
        with RunLock(lock_root, run["run_id"]):
            return execute_run_locked(
                run, experiment_path, dataset_root, args, preflight, attempt_id
            )
    except Exception as error:
        artifact_dir = preflight["artifact_dir"]
        state_path = artifact_dir / preflight["execution_policy"]["artifacts"]["state_file"]
        if artifact_dir.is_dir():
            prior = load_state(state_path) or {}
            atomic_write_json(state_path, {
                "schema_version": "1.0",
                "run_id": run["run_id"],
                "attempt_id": attempt_id,
                "status": "error",
                "started_at": prior.get("started_at"),
                "finished_at": utc_now(),
                "error": redact_text(str(error), credential_values(
                    preflight["agent"], preflight["runtime"]
                ))
            })
        raise
    finally:
        if preflight["execution_policy"]["workspace"].get(
            "remove_injected_secret_config_after_run"
        ):
            remove_workspace_secret_config(preflight)


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
    rerun = parser.add_mutually_exclusive_group()
    rerun.add_argument("--force", action="store_true")
    rerun.add_argument(
        "--resume",
        action="store_true",
        help="skip completed runs and rebuild failed/incomplete attempts"
    )
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument(
        "--preflight",
        action="store_true",
        help="validate paths, configs, credentials, and executables without running agents"
    )
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
    if plan.get("experiment_id") != experiment.get("experiment_id"):
        raise SystemExit("run plan experiment_id does not match experiment")
    if plan.get("benchmark_manifest") != experiment.get("benchmark_manifest"):
        raise SystemExit("run plan benchmark_manifest does not match experiment")
    if plan.get("context_policy") != experiment.get("context_policy"):
        raise SystemExit("run plan context_policy does not match experiment")
    run_ids = [run.get("run_id") for run in plan.get("runs", [])]
    if len(run_ids) != len(set(run_ids)):
        raise SystemExit("run plan contains duplicate run IDs")
    dataset_root = experiment_path.parent.parent

    runs = plan["runs"]
    if args.run_id:
        requested = set(args.run_id)
        missing = sorted(requested - set(run_ids))
        if missing:
            raise SystemExit(f"requested run IDs not found: {missing}")
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
    if args.preflight and args.dry_run:
        raise SystemExit("--preflight and --dry-run are mutually exclusive")

    def run_one(run):
        try:
            if args.preflight:
                checked = preflight_run(
                    run, experiment_path, dataset_root, require_executable=True
                )
                return {
                    "run_id": run["run_id"],
                    "status": "ready",
                    "program": checked["program"],
                    "workspace": str(checked["workspace"]),
                    "artifact_dir": str(checked["artifact_dir"]),
                    "required_environment": checked["required_environment"]
                }
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
        "incomplete": sum(result["status"] == "incomplete" for result in results),
        "error": sum(result["status"] == "error" for result in results),
        "skipped": sum(result["status"] == "skipped" for result in results),
        "dry_run": sum(result["status"] == "dry-run" for result in results),
        "ready": sum(result["status"] == "ready" for result in results)
    }
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    if any(
        result["status"] in ("failed", "timeout", "incomplete", "error")
        for result in results
    ):
        sys.exit(1)


if __name__ == "__main__":
    main()
