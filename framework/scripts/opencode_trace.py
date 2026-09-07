#!/usr/bin/env python3
"""Normalize an opencode run session (stored in opencode.db SQLite) into a
portable trace.json event sequence.

Normalized event kinds
----------------------
tool_call        {type, tool, target, duration_ms, doc_type, ts}
assistant_output {type, message_id, text, reasoning, ts}   # reasoning merged in
finish           {type, stop_reason, tokens, cost, ts}

doc_type is a four-way classification of ``target``:
    injected / doc / code / other
Priority: injected > code > doc > other.

Classification inputs (optional, per project card ground_truth):
    injected_files / doc_globs / code_globs
When a field is absent a conservative built-in default is used.  ``injected``
additionally always matches the per-run carrier from context_overlay.

The exact opencode part JSON shapes (tool/reasoning/text parts) are inferred
from the installed opencode 1.17 DB schema; validate on a live run before
final reporting (see trace_extract / run_agent smoke checklist).
"""

import argparse
import json
import os
import re
import sqlite3
from fnmatch import fnmatch
from pathlib import Path

# --- doc_type defaults ------------------------------------------------------

DEFAULT_DOC_GLOBS = [
    "docs/**", "**/*.md", "**/*.markdown", "**/*.rst",
    "**/README*", "**/SECURITY*", "**/CHANGELOG*", "**/CONTRIBUTING*",
    "**/LICENSE*", "**/NOTICE*", "**/AUTHORS*", "**/THREAT_MODEL*",
    "**/AUDIT_SCOPE*", "**/*CHANGES*",
]
CODE_EXTS = {
    ".py", ".java", ".c", ".cc", ".cpp", ".h", ".hpp", ".hh", ".go", ".rs",
    ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".php", ".rb", ".pl", ".pm",
    ".sh", ".bash", ".zsh", ".kt", ".kts", ".scala", ".swift", ".cs", ".vue",
    ".svelte", ".sql", ".groovy", ".gradle",
}
DOC_EXTS = {".md", ".markdown", ".rst", ".adoc", ".txt"}
TOOL_PATH_KEYS = ("filePath", "file_path", "path", "filename")
LOC_RE = re.compile(r":\d+(?:[-:]\d+)*$")


def default_data_home():
    xdg = os.environ.get("XDG_DATA_HOME")
    if xdg:
        return Path(xdg)
    home = Path(os.environ.get("USERPROFILE", str(Path.home())))
    return home / ".local" / "share"


def opencode_db_path(data_home=None):
    return (data_home or default_data_home()) / "opencode" / "opencode.db"


def _norm(value):
    if not value:
        return ""
    return str(value).replace("\\", "/").strip()


def _relativize(target, repo_root):
    t = _norm(target).lstrip("/")
    if repo_root:
        r = _norm(repo_root).rstrip("/")
        if r and t.startswith(r + "/"):
            t = t[len(r) + 1:]
        # tolerate windows drive prefix remnants
        m = re.match(r"^[A-Za-z]:(/.*)$", t)
        if m:
            t = m.group(1).lstrip("/")
    return t


def _match_glob(rel, patterns):
    for pattern in patterns:
        p = pattern.replace("\\", "/")
        if fnmatch(rel, p):
            return True
        if "/" not in p and fnmatch(rel.rsplit("/", 1)[-1], p):
            return True
    return False


def classify_target(target, carrier=None, ground_truth=None, repo_root=None):
    """Return one of injected/doc/code/other for a target path."""
    rel = _relativize(target, repo_root)
    if not rel:
        return "other"
    gt = ground_truth or {}
    injected = [carrier] if carrier else []
    injected += gt.get("injected_files", []) or []
    for f in injected:
        f = _norm(f)
        if f and (rel == f or rel.endswith("/" + f)):
            return "injected"
    code_globs = gt.get("code_globs", []) or []
    doc_globs = gt.get("doc_globs", []) or DEFAULT_DOC_GLOBS
    if _match_glob(rel, code_globs):
        return "code"
    if _match_glob(rel, doc_globs):
        return "doc"
    suffix = "." + rel.rsplit(".", 1)[-1].lower() if "." in rel.rsplit("/", 1)[-1] else ""
    if suffix in CODE_EXTS:
        return "code"
    if suffix in DOC_EXTS:
        return "doc"
    return "other"


def _as_ms(value):
    return int(value) if isinstance(value, (int, float)) else None


def _part_text(part_data):
    t = part_data.get("text")
    if isinstance(t, str):
        return t
    out = part_data.get("output")
    if isinstance(out, list):
        return "".join(
            x.get("text", "") for x in out if isinstance(x, dict) and x.get("type") == "text"
        )
    return ""


def _tool_target(part_data):
    state = part_data.get("state") or {}
    inp = state.get("input") or {}
    for key in TOOL_PATH_KEYS:
        if isinstance(inp, dict) and inp.get(key):
            return inp[key]
    command = inp.get("command") if isinstance(inp, dict) else None
    if command:
        m = re.search(r"([A-Za-z0-9_./\\-]+\.(?:py|java|c|cc|cpp|h|hpp|go|rs|js|ts|php|rb|sh|md|txt|xml|json|yml|yaml|properties))", str(command))
        if m:
            return m.group(1)
    return ""


def _tool_duration(part_data, part_time_created, part_time_updated):
    t = part_data.get("time") or {}
    start = _as_ms(t.get("created")) if t.get("created") is not None else part_time_created
    end = _as_ms(t.get("completed")) if t.get("completed") is not None else part_time_updated
    if start is not None and end is not None:
        return max(0, end - start)
    return None


def load_session(db_path, title):
    """Return (session_row, messages) where messages are (message_data, [parts])."""
    db_path = Path(db_path)
    if not db_path.is_file():
        raise FileNotFoundError(f"opencode db not found: {db_path}")
    con = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        cur = con.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='session'")
        if not cur.fetchone():
            raise RuntimeError(f"no session table in {db_path} (wrong opencode version?)")
        cur.execute(
            "SELECT id, title, directory, model, cost, tokens_input, tokens_output, "
            "tokens_reasoning, time_created, time_updated FROM session WHERE title=? "
            "ORDER BY time_created DESC LIMIT 1",
            (title,),
        )
        row = cur.fetchone()
        if not row:
            return None, None
        session = {
            "id": row[0], "title": row[1], "directory": row[2],
            "model": row[3], "cost": row[4], "tokens_input": row[5],
            "tokens_output": row[6], "tokens_reasoning": row[7],
            "time_created": row[8], "time_updated": row[9],
        }
        cur.execute("SELECT id, session_id, time_created, time_updated, data FROM message WHERE session_id=? ORDER BY time_created", (session["id"],))
        message_rows = cur.fetchall()
        messages = []
        for mid, sid, tc, tu, data in message_rows:
            try:
                mdata = json.loads(data) if data else {}
            except json.JSONDecodeError:
                mdata = {"role": "unknown", "parse_error": True}
            cur.execute("SELECT id, message_id, session_id, time_created, time_updated, data FROM part WHERE message_id=? ORDER BY time_created", (mid,))
            parts = []
            for pid, pmid, psid, ptc, ptu, pdata in cur.fetchall():
                try:
                    pd = json.loads(pdata) if pdata else {}
                except json.JSONDecodeError:
                    pd = {"type": "unknown", "parse_error": True}
                parts.append({
                    "id": pid, "time_created": ptc, "time_updated": ptu, "data": pd,
                })
            messages.append({"id": mid, "time_created": tc, "time_updated": tu, "data": mdata, "parts": parts})
        return session, messages
    finally:
        con.close()


def normalize(session, messages, carrier=None, ground_truth=None, repo_root=None):
    events = []
    for msg in messages:
        role = msg["data"].get("role")
        ts = msg["time_created"]
        if role == "user":
            # user prompt is preserved separately as prompt.txt; the normalized
            # event schema only keeps tool_call / assistant_output / finish.
            continue
        # assistant message: merge text + reasoning into one assistant_output
        text_parts, reasoning = [], []
        for part in msg["parts"]:
            pd = part["data"]
            ptype = pd.get("type")
            if ptype == "text":
                text_parts.append(_part_text(pd))
            elif ptype == "reasoning":
                reasoning.append(_part_text(pd))
            elif ptype == "tool":
                target = _tool_target(pd)
                rel_target = _relativize(target, repo_root)
                events.append({
                    "type": "tool_call",
                    "tool": pd.get("tool") or pd.get("name") or "unknown",
                    "target": rel_target,
                    "duration_ms": _tool_duration(pd, part["time_created"], part["time_updated"]),
                    "doc_type": classify_target(target, carrier=carrier, ground_truth=ground_truth, repo_root=repo_root),
                    "ts": part["time_created"],
                })
        text = "\n\n".join(t for t in text_parts if t)
        if text or reasoning:
            events.append({
                "type": "assistant_output",
                "message_id": msg["id"],
                "text": text,
                "reasoning": "\n\n".join(r for r in reasoning if r),
                "ts": ts,
            })
    events.append({
        "type": "finish",
        "stop_reason": None,
        "tokens": {
            "input": session.get("tokens_input"),
            "output": session.get("tokens_output"),
            "reasoning": session.get("tokens_reasoning"),
        },
        "cost": session.get("cost"),
        "ts": session.get("time_updated"),
    })
    return events


def harvest(run_id, repo_root=None, carrier=None, ground_truth=None,
            db_path=None, data_home=None):
    """Load opencode session for run_id (session title == run_id) and return
    (session, events).  Raises when no DB/session is found."""
    db = Path(db_path) if db_path else opencode_db_path(data_home)
    session, messages = load_session(db, run_id)
    if session is None:
        raise LookupError(f"no opencode session with title {run_id!r} in {db}")
    events = normalize(session, messages, carrier=carrier, ground_truth=ground_truth, repo_root=repo_root)
    return session, events


def main():
    ap = argparse.ArgumentParser(description="Inspect/normalize an opencode session from opencode.db")
    ap.add_argument("--db", help="path to opencode.db (default: data home)")
    ap.add_argument("--title", required=True, help="session title (run_id)")
    ap.add_argument("--repo-root", help="repository root for relativizing targets")
    ap.add_argument("--carrier", help="injected carrier path (repo-relative)")
    ap.add_argument("--gt", help="project card JSON path (optional ground_truth classification)")
    ap.add_argument("--out", help="write trace.json here")
    args = ap.parse_args()
    gt = json.loads(Path(args.gt).read_text(encoding="utf-8")).get("ground_truth", {}) if args.gt else {}
    session, events = harvest(
        args.title,
        repo_root=args.repo_root,
        carrier=args.carrier,
        ground_truth=gt,
        db_path=args.db,
    )
    print("session:", session["id"], "events:", len(events))
    for e in events:
        print(json.dumps(e, ensure_ascii=False))
    if args.out:
        out = Path(args.out)
        out.write_text(
            json.dumps({"source": "opencode-db", "session": session, "events": events}, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8", newline="\n")
        print("wrote", out)


if __name__ == "__main__":
    main()
