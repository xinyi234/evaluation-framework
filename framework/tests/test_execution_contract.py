#!/usr/bin/env python3
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

from execution_contract import (  # noqa: E402
    RunLock,
    atomic_write_json,
    canonical_sha256,
    credential_values,
    load_state,
    redact_text,
    resolve_child,
    run_command,
    tree_manifest_sha256,
    validate_completed_artifacts,
    validate_execution_policy,
    validate_run_id,
)


class ExecutionContractTests(unittest.TestCase):
    def test_resolve_child_rejects_escape_and_root(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.assertEqual(resolve_child(root, "a/b", "test"), (root / "a/b").resolve())
            with self.assertRaises(ValueError):
                resolve_child(root, "../escape", "test")
            with self.assertRaises(ValueError):
                resolve_child(root, ".", "test")

    def test_run_id_and_lock_are_exclusive(self):
        with tempfile.TemporaryDirectory() as directory:
            validate_run_id("P01__clean__agent-v1__r01")
            with self.assertRaises(ValueError):
                validate_run_id("../unsafe")
            with RunLock(directory, "run-1"):
                with self.assertRaises(RuntimeError):
                    with RunLock(directory, "run-1"):
                        pass
            with RunLock(directory, "run-1"):
                pass
            stale = Path(directory) / "stale.lock"
            stale.write_text(json.dumps({"pid": 99999999}), encoding="utf-8")
            with RunLock(directory, "stale"):
                pass

    def test_atomic_state_and_deterministic_hash(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            atomic_write_json(path, {"status": "running"})
            self.assertEqual(load_state(path)["status"], "running")
            self.assertEqual(canonical_sha256({"b": 2, "a": 1}), canonical_sha256({"a": 1, "b": 2}))

    def test_tree_manifest_detects_changes_and_honors_exclusions(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "source.py").write_text("before\n", encoding="utf-8")
            (root / ".sessions").mkdir()
            (root / ".sessions" / "trace.jsonl").write_text("one\n", encoding="utf-8")
            before = tree_manifest_sha256(root, [".sessions"])
            (root / ".sessions" / "trace.jsonl").write_text("two\n", encoding="utf-8")
            self.assertEqual(before, tree_manifest_sha256(root, [".sessions"]))
            (root / "source.py").write_text("after\n", encoding="utf-8")
            self.assertNotEqual(before, tree_manifest_sha256(root, [".sessions"]))

    def test_secret_redaction_uses_only_credential_variables(self):
        agent = {"secret_injections": [{"environment_variable": "API_KEY"}]}
        runtime = {"environment_passthrough": ["PATH", "ACCESS_TOKEN"]}
        env = {"API_KEY": "alpha", "ACCESS_TOKEN": "beta", "PATH": "do-not-redact"}
        secrets = credential_values(agent, runtime, env)
        self.assertEqual(redact_text("alpha beta do-not-redact", secrets), "<redacted> <redacted> do-not-redact")

    def test_run_command_completes_and_times_out(self):
        code, stdout, stderr, timed_out = run_command(
            [sys.executable, "-c", "print('ok')"],
            None,
            Path.cwd(),
            os.environ.copy(),
            5,
        )
        self.assertEqual((code, stdout.strip(), stderr, timed_out), (0, "ok", "", False))
        code, _, stderr, timed_out = run_command(
            [sys.executable, "-c", "import time; time.sleep(5)"],
            None,
            Path.cwd(),
            os.environ.copy(),
            0.1,
        )
        self.assertEqual(code, 124)
        self.assertTrue(timed_out)
        self.assertIn("agent timeout", stderr)

    def test_policy_and_completed_artifacts(self):
        policy = {
            "schema_version": "1.0",
            "workspace": {"fresh_per_attempt": True},
            "concurrency": {"per_run_lock": True},
            "existing_artifacts": {
                "skip_completed": True,
                "require_resume_for_incomplete": True,
            },
            "artifacts": {
                "state_file": "run_state.json",
                "required_for_completed": [
                    "metadata.json", "prompt.txt", "agent_config.json",
                    "context_overlay.json", "report.md", "verdict.json", "trace.json",
                ],
                "require_nonempty_report": True,
                "require_parsed_verdict": True,
                "require_nonempty_trace_when_configured": True,
            },
        }
        self.assertEqual(validate_execution_policy(policy), [])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in policy["artifacts"]["required_for_completed"]:
                (root / name).write_text("{}\n", encoding="utf-8")
            (root / "report.md").write_text("VERDICT: High\nSEVERITY: 3\n", encoding="utf-8")
            (root / "trace.json").write_text(json.dumps({"events": [{"type": "finish"}]}), encoding="utf-8")
            self.assertEqual(
                validate_completed_artifacts(root, {"trace_source": "stdout_jsonl"}, {}, policy),
                [],
            )
            (root / "trace.json").write_text(json.dumps({"events": []}), encoding="utf-8")
            self.assertIn(
                "trace.json has no events",
                validate_completed_artifacts(root, {"trace_source": "stdout_jsonl"}, {}, policy),
            )


if __name__ == "__main__":
    unittest.main()
