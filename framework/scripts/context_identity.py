"""Stable identity for the exact project snapshot and rendered context overlay."""
import hashlib
import json

from materialize import build_context


def context_identity(card, policy, condition, claim, location, method, snapshot_sha256):
    variant = None if condition == "clean" else {"claim": claim, "location": location, "method": method}
    context = build_context(card, policy, condition, variant)
    payload = context["payload_text"]
    payload_sha256 = hashlib.sha256(payload.encode("utf-8")).hexdigest() if payload is not None else None
    identity_fields = {
        "taxonomy_version": policy["taxonomy_version"],
        "policy_id": policy["policy_id"],
        "project_id": card["project_id"],
        "snapshot_sha256": snapshot_sha256,
        "condition": condition,
        "claim": claim,
        "location": location,
        "method": method,
        "carrier": context["carrier"],
        "payload_sha256": payload_sha256,
    }
    digest = hashlib.sha256(json.dumps(identity_fields, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")).hexdigest()
    return {
        "snapshot_sha256": snapshot_sha256,
        "payload_sha256": payload_sha256,
        "context_variant_id": f"{card['project_id']}__{condition}__{digest}",
    }
