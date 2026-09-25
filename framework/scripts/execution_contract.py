#!/usr/bin/env python3
import hashlib
import json
import os
import re
import signal
import subprocess
from datetime import datetime, timezone
from pathlib import Path


RUN_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
SECRET_NAME_PATTERN = re.compile(r"(?:KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL)$", re.IGNORECASE)


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def canonical_sha256(value):
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def tree_manifest_sha256(root, excluded=None):
    root = Path(root).resolve()
    excluded = {
        Path(item).as_posix().strip("/")
        for item in (excluded or [])
        if item
    }

    def is_excluded(relative):
        value = relative.as_posix()
        return any(value == item or value.startswith(item + "/") for item in excluded)

    records = []
    for directory, directory_names, file_names in os.walk(root, followlinks=False):
        directory_path = Path(directory)
        directory_names[:] = sorted(
            name for name in directory_names
            if not is_excluded((directory_path / name).relative_to(root))
        )
        for name in sorted(file_names):
            path = directory_path / name
            relative = path.relative_to(root)
            if is_excluded(relative):
                continue
            if path.is_symlink():
                records.append([relative.as_posix(), "symlink", os.readlink(path)])
                continue
            digest = hashlib.sha256()
            with path.open("rb") as source:
                while True:
                    block = source.read(1024 * 1024)
                    if not block:
                        break
                    digest.update(block)
            records.append([relative.as_posix(), "file", digest.hexdigest()])
    return canonical_sha256(records)


def resolve_child(root, relative, label, allow_root=False):
    root = Path(root).resolve()
    candidate = Path(relative)
    if candidate.is_absolute():
        raise ValueError(f"{label} must be relative: {relative}")
    resolved = (root / candidate).resolve()
    if not resolved.is_relative_to(root) or (resolved == root and not allow_root):
        raise ValueError(f"{label} escapes its root: {relative}")
    return resolved


def validate_run_id(run_id):
    if not isinstance(run_id, str) or not RUN_ID_PATTERN.fullmatch(run_id):
        raise ValueError(f"unsafe run_id: {run_id!r}")
    return run_id


def atomic_write_json(path, payload):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
        newline="\n"
    )
    temporary.replace(path)


def load_state(path):
    path = Path(path)
    if not path.is_file():
        return None
    try:
        state = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return state if isinstance(state, dict) else None


def credential_values(agent, runtime, environ=None):
    environ = os.environ if environ is None else environ
    names = {
        injection.get("environment_variable")
        for injection in agent.get("secret_injections", [])
    }
    names.update(
        name for name in runtime.get("environment_passthrough", [])
        if SECRET_NAME_PATTERN.search(name)
    )
    return sorted(
        {
            environ[name]
            for name in names
            if name and isinstance(environ.get(name), str) and environ[name]
        },
        key=len,
        reverse=True
    )


def redact_text(text, secrets):
    redacted = text
    for secret in secrets:
        redacted = redacted.replace(secret, "<redacted>")
    return redacted


def terminate_process_tree(process):
    if process.poll() is not None:
        return
    if os.name == "nt":
        subprocess.run(
            ["taskkill", "/PID", str(process.pid), "/T", "/F"],
            capture_output=True,
            check=False,
            text=True
        )
    else:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    if process.poll() is None:
        process.kill()


def run_command(command, prompt, cwd, environment, timeout_s):
    options = {
        "cwd": str(cwd),
        "env": environment,
        "stdin": subprocess.PIPE if prompt is not None else subprocess.DEVNULL,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "text": True,
        "encoding": "utf-8",
        "errors": "replace"
    }
    if os.name == "nt":
        options["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        options["start_new_session"] = True
    process = subprocess.Popen(command, **options)
    try:
        stdout, stderr = process.communicate(input=prompt, timeout=timeout_s)
        return process.returncode, stdout, stderr, False
    except subprocess.TimeoutExpired:
        terminate_process_tree(process)
        try:
            stdout, stderr = process.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = process.communicate()
        return 124, stdout, stderr + "\n[runner] agent timeout\n", True


def validate_execution_policy(policy):
    errors = []
    if policy.get("schema_version") != "1.0":
        errors.append("execution policy schema_version must be 1.0")
    required_true = [
        ("workspace.fresh_per_attempt", policy.get("workspace", {}).get("fresh_per_attempt")),
        ("concurrency.per_run_lock", policy.get("concurrency", {}).get("per_run_lock")),
        ("existing_artifacts.skip_completed", policy.get("existing_artifacts", {}).get("skip_completed")),
        (
            "existing_artifacts.require_resume_for_incomplete",
            policy.get("existing_artifacts", {}).get("require_resume_for_incomplete")
        )
    ]
    for name, value in required_true:
        if value is not True:
            errors.append(f"execution policy requires {name}=true")
    artifacts = policy.get("artifacts", {})
    required = artifacts.get("required_for_completed")
    if not isinstance(required, list) or not required:
        errors.append("execution policy artifacts.required_for_completed must be non-empty")
    elif any(not isinstance(item, str) or not item for item in required):
        errors.append("execution policy required artifact names must be non-empty strings")
    state_file = artifacts.get("state_file")
    if not isinstance(state_file, str) or not state_file:
        errors.append("execution policy artifacts.state_file must be set")
    else:
        try:
            resolve_child(Path("policy-root"), state_file, "state_file")
        except ValueError as error:
            errors.append(str(error))
    return errors


def validate_completed_artifacts(artifact_dir, runtime, verdict, policy):
    artifact_dir = Path(artifact_dir).resolve()
    artifacts = policy["artifacts"]
    errors = []
    for relative in artifacts["required_for_completed"]:
        try:
            path = resolve_child(artifact_dir, relative, "required artifact")
        except ValueError as error:
            errors.append(str(error))
            continue
        if not path.is_file():
            errors.append(f"required artifact missing: {relative}")

    report_path = artifact_dir / "report.md"
    if artifacts.get("require_nonempty_report") and (
        not report_path.is_file() or not report_path.read_text(encoding="utf-8", errors="replace").strip()
    ):
        errors.append("report.md is empty")
    if artifacts.get("require_parsed_verdict") and verdict.get("parse_error"):
        errors.append(f"verdict parse failed: {verdict['parse_error']}")

    trace_path = artifact_dir / "trace.json"
    if artifacts.get("require_nonempty_trace_when_configured") \
            and runtime.get("trace_source") not in (None, "none"):
        try:
            trace = json.loads(trace_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            trace = {}
        if not isinstance(trace.get("events"), list) or not trace["events"]:
            errors.append("trace.json has no events")
    return errors


class RunLock:
    def __init__(self, locks_root, run_id):
        validate_run_id(run_id)
        self.locks_root = Path(locks_root).resolve()
        self.path = self.locks_root / f"{run_id}.lock"
        self.fd = None

    def __enter__(self):
        self.locks_root.mkdir(parents=True, exist_ok=True)
        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
        try:
            self.fd = os.open(self.path, flags)
        except FileExistsError as error:
            try:
                payload = json.loads(self.path.read_text(encoding="utf-8"))
                pid = int(payload.get("pid"))
                os.kill(pid, 0)
            except (OSError, ValueError, TypeError, json.JSONDecodeError):
                try:
                    self.path.unlink()
                except FileNotFoundError:
                    pass
                self.fd = os.open(self.path, flags)
            else:
                raise RuntimeError(f"run is already locked: {self.path.name}") from error
        payload = json.dumps({"pid": os.getpid(), "created_at": utc_now()}) + "\n"
        os.write(self.fd, payload.encode("utf-8"))
        os.close(self.fd)
        self.fd = None
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None
        try:
            self.path.unlink()
        except FileNotFoundError:
            pass
