#!/usr/bin/env python3
import argparse
import re
import zipfile
from collections import Counter, defaultdict
from pathlib import Path

from common import load_agents, load_benchmark, load_json, sha256, snapshot_path


REQUIRED_SNAPSHOT_FIELDS = [
    "archive", "root_directory", "ref", "ref_type",
    "upstream_archive_url", "immutability"
]
REQUIRED_GROUND_TRUTH_FIELDS = [
    "vul_files", "entry_points", "fix_commit", "affected_range",
    "finding_match_rule", "safe_reproduction_predicate", "sources"
]
ALLOWED_RUNTIME_PLACEHOLDERS = {
    "{workspace}", "{prompt_file}", "{report}", "{trace}", "{artifact_dir}",
    "{model}", "{agent_config}", "{context_policy}", "{benchmark_manifest}",
    "{run_id}"
}
ALLOWED_CLAIM_PLACEHOLDERS = {"{affected_areas}"}
ALLOWED_METHOD_PLACEHOLDERS = {"{location_title}", "{claim_body}", "{claim_closing}"}
EXPECTED_CLAIMS = {"C1", "C2", "C3", "C4", "C5", "C6"}
EXPECTED_LOCATIONS = {"L1", "L2", "L5", "L6"}
EXPECTED_METHODS = {"M1", "M2", "M3", "M7"}
REQUIRED_METHOD_ATTRIBUTES = {
    "expression", "authority_cue", "normative_framing", "distribution",
    "representation", "prior_output_framing"
}
BENIGN_FORBIDDEN_RE = re.compile(
    r"\b(?:must|should|audit findings?|security conclusions?|vulnerabilit(?:y|ies)|"
    r"based on (?:source )?code|do not|must not)\b",
    re.IGNORECASE
)
WRAPPER_DIRECTIVE_RE = re.compile(
    r"\b(?:must|should|do not|must not|mandatory|approved|final|"
    r"no (?:new )?finding|not be reported)\b",
    re.IGNORECASE
)


def validate_zip(project_id, path, expected_root):
    errors = []
    if not path.is_file():
        return [f"{project_id}: snapshot zip not found: {path}"]
    try:
        with zipfile.ZipFile(path) as archive:
            roots = {name.split("/", 1)[0] for name in archive.namelist() if name.strip()}
            if roots != {expected_root}:
                errors.append(
                    f"{project_id}: zip root mismatch, expected {expected_root}, found {sorted(roots)}"
                )
            unsafe = [
                name for name in archive.namelist()
                if name.startswith("/") or ".." in Path(name).parts
            ]
            if unsafe:
                errors.append(f"{project_id}: unsafe zip entry {unsafe[:3]}")
    except Exception as error:
        errors.append(f"{project_id}: cannot open zip: {error}")
    return errors


def safe_relative_path(value):
    if not isinstance(value, str) or not value:
        return False
    path = Path(value)
    return not path.is_absolute() and ".." not in path.parts


def template_placeholders(value):
    if not isinstance(value, str):
        return set()
    return set(re.findall(r"\{[^}]+\}", value))


def validate_context_policy(policy):
    errors = []
    if policy.get("schema_version") != "4.0":
        return ["context policy schema_version must be 4.0"], set()
    if policy.get("semantic_contract_version") != "1.0":
        errors.append("context policy semantic_contract_version must be 1.0")

    contract = policy.get("annotation_contract", {})
    contract_fields = {
        "content_modes", "factual_statuses", "rule_authorities",
        "rule_applicabilities", "evidence_relations", "agent_evidence_access"
    }
    if not contract_fields.issubset(contract):
        errors.append("context policy annotation contract is incomplete")

    content_modes = set(contract.get("content_modes", []))
    factual_statuses = set(contract.get("factual_statuses", []))
    rule_authorities = set(contract.get("rule_authorities", []))
    rule_applicabilities = set(contract.get("rule_applicabilities", []))
    evidence_relations = set(contract.get("evidence_relations", []))
    evidence_access = set(contract.get("agent_evidence_access", []))

    claims = policy.get("claim_categories", {})
    if set(claims) != EXPECTED_CLAIMS:
        errors.append(f"context policy claim categories must be {sorted(EXPECTED_CLAIMS)}")
    claim_names = set()
    for claim_id, claim in claims.items():
        name = claim.get("name")
        if not isinstance(name, str) or not name:
            errors.append(f"context policy claim {claim_id} has no name")
        elif name in claim_names:
            errors.append(f"context policy has duplicate claim name {name}")
        else:
            claim_names.add(name)
        required = {
            "content_mode", "intended_goal", "truthfulness", "factual_status",
            "rule_authority", "rule_applicability", "evidence_relation",
            "evidence_reference", "required_evidence", "agent_evidence_access",
            "verifiability", "primary_analysis_eligible", "body_template", "closing"
        }
        missing = sorted(required - set(claim))
        if missing:
            errors.append(f"context policy claim {claim_id} is missing fields {missing}")
            continue
        content_mode = claim["content_mode"]
        if content_mode not in content_modes or content_mode == "neutral_control":
            errors.append(f"context policy claim {claim_id} has invalid content_mode")
        if content_mode == "behavioral_directive":
            errors.append(f"context policy claim {claim_id} cannot be a behavioral directive")
        if claim["factual_status"] not in factual_statuses:
            errors.append(f"context policy claim {claim_id} has invalid factual_status")
        if claim["rule_authority"] not in rule_authorities:
            errors.append(f"context policy claim {claim_id} has invalid rule_authority")
        if claim["rule_applicability"] not in rule_applicabilities:
            errors.append(f"context policy claim {claim_id} has invalid rule_applicability")
        if claim["evidence_relation"] not in evidence_relations:
            errors.append(f"context policy claim {claim_id} has invalid evidence_relation")
        if claim["agent_evidence_access"] not in evidence_access:
            errors.append(f"context policy claim {claim_id} has invalid agent_evidence_access")
        if content_mode == "descriptive_claim":
            if claim["factual_status"] == "not_applicable":
                errors.append(f"descriptive claim {claim_id} requires a factual_status")
            if claim["rule_authority"] != "not_applicable" \
                    or claim["rule_applicability"] != "not_applicable":
                errors.append(f"descriptive claim {claim_id} cannot use normative rule labels")
        if content_mode == "normative_rule":
            if claim["factual_status"] != "not_applicable":
                errors.append(f"normative rule {claim_id} must use factual_status=not_applicable")
            if claim["rule_authority"] == "not_applicable" \
                    or claim["rule_applicability"] == "not_applicable":
                errors.append(f"normative rule {claim_id} requires authority and applicability labels")
        if not isinstance(claim["evidence_reference"], str) or not claim["evidence_reference"]:
            errors.append(f"context policy claim {claim_id} requires an evidence_reference")
        if not isinstance(claim["required_evidence"], list) or not claim["required_evidence"]:
            errors.append(f"context policy claim {claim_id} requires evidence sources")
        if not isinstance(claim["primary_analysis_eligible"], bool):
            errors.append(f"context policy claim {claim_id} has invalid primary_analysis_eligible")
        if claim["primary_analysis_eligible"] is False and not claim.get("eligibility_blocker"):
            errors.append(f"ineligible claim {claim_id} requires an eligibility_blocker")
        if claim.get("verifiability") not in (
            "repo_verifiable", "code_verifiable", "environment_verifiable",
            "history_verifiable", "task_verifiable"
        ):
            errors.append(f"context policy claim {claim_id} has invalid verifiability")
        placeholders = template_placeholders(claim.get("body_template"))
        if placeholders != ALLOWED_CLAIM_PLACEHOLDERS:
            errors.append(
                f"context policy claim {claim_id} must use only {{affected_areas}}"
            )

    locations = policy.get("locations", {})
    if set(locations) != EXPECTED_LOCATIONS:
        errors.append(f"context policy main locations must be {sorted(EXPECTED_LOCATIONS)}")
    for location_id, location in locations.items():
        carrier = location.get("carrier")
        if not safe_relative_path(carrier) or not carrier.endswith(".md"):
            errors.append(f"context policy location {location_id} must use a safe Markdown carrier")
        if location.get("executable") is not False:
            errors.append(f"context policy location {location_id} must be non-executable")
        if "trust_profile" in location:
            errors.append(f"context policy location {location_id} cannot hard-code a trust profile")
        for field in ("carrier_family", "document_role", "artifact_format", "asserted_source"):
            if not isinstance(location.get(field), str) or not location[field]:
                errors.append(f"context policy location {location_id} requires {field}")
        if location.get("artifact_format") != "markdown":
            errors.append(f"context policy location {location_id} must declare markdown format")
    if locations.get("L5", {}).get("carrier_family") != "project_documentation":
        errors.append("L5 is documentation, not deployment or tooling configuration")
    if locations.get("L6", {}).get("carrier_family") != "project_documentation":
        errors.append("L6 is documentation, not package or dependency metadata")

    methods = policy.get("methods", {})
    if set(methods) != EXPECTED_METHODS:
        errors.append(f"context policy main methods must be {sorted(EXPECTED_METHODS)}")
    for method_id, method in methods.items():
        placeholders = template_placeholders(method.get("wrapper_template"))
        if placeholders != ALLOWED_METHOD_PLACEHOLDERS:
            errors.append(
                f"context policy method {method_id} must use all and only the wrapper placeholders"
            )
        attributes = method.get("attributes", {})
        missing = sorted(REQUIRED_METHOD_ATTRIBUTES - set(attributes))
        if missing:
            errors.append(f"context policy method {method_id} is missing attributes {missing}")
        if not isinstance(attributes.get("prior_output_framing"), bool):
            errors.append(f"context policy method {method_id} has invalid prior_output_framing")
        wrapper_without_placeholders = re.sub(r"\{[^}]+\}", "", method.get("wrapper_template", ""))
        if WRAPPER_DIRECTIVE_RE.search(wrapper_without_placeholders):
            errors.append(f"context policy method {method_id} wrapper adds directive semantics")

    main_levels = policy.get("main_levels", {})
    if main_levels.get("claims") != sorted(EXPECTED_CLAIMS):
        errors.append("context policy main claim levels are incomplete or unordered")
    if main_levels.get("locations") != sorted(EXPECTED_LOCATIONS):
        errors.append("context policy main location levels are incomplete or unordered")
    if main_levels.get("methods") != sorted(EXPECTED_METHODS):
        errors.append("context policy main method levels are incomplete or unordered")

    benign = policy.get("benign", {})
    if set(benign.get("templates_by_location", {})) != EXPECTED_LOCATIONS:
        errors.append("context policy benign templates must cover all main locations")
    if benign.get("truthfulness") != "not_applicable":
        errors.append("context policy benign truthfulness must be not_applicable")
    if benign.get("verifiability") != "non_decisive_control":
        errors.append("context policy benign verifiability must be non_decisive_control")
    if benign.get("content_mode") != "neutral_control":
        errors.append("context policy benign content_mode must be neutral_control")
    for field in (
        "factual_status", "rule_authority", "rule_applicability",
        "evidence_relation", "agent_evidence_access"
    ):
        if benign.get(field) != "not_applicable":
            errors.append(f"context policy benign {field} must be not_applicable")
    for location_id, template in benign.get("templates_by_location", {}).items():
        if template_placeholders(template) != ALLOWED_CLAIM_PLACEHOLDERS:
            errors.append(f"benign template {location_id} must use only {{affected_areas}}")
        if BENIGN_FORBIDDEN_RE.search(template):
            errors.append(f"benign template {location_id} contains security or grounding guidance")

    allocation = policy.get("allocation", {})
    formula = allocation.get("formula", {})
    required_formula_fields = {"cell_index", "pair_index", "location_index", "method_index"}
    if not required_formula_fields.issubset(formula):
        errors.append("context policy allocation formula is incomplete")
    if not allocation.get("benign_location_formula"):
        errors.append("context policy benign location formula is missing")

    required_constraints = {
        "one_atomic_security_item_per_manipulated_variant",
        "one_non_executable_carrier_per_manipulated_variant",
        "method_wrapper_changes_presentation_not_claim_semantics",
        "wrapper_adds_no_security_proposition_or_behavioral_directive",
        "neutral_control_contains_no_security_conclusion_or_grounding_instruction",
        "all_introduced_text_is_annotated",
        "no_agent_control_instructions"
    }
    if not required_constraints.issubset(set(policy.get("payload_constraints", []))):
        errors.append("context policy payload constraints are incomplete")
    return errors, claim_names


def validate_experiment(experiment, policy, agents, project_count):
    errors = []
    if experiment.get("schema_version") != "4.0":
        errors.append("experiment schema_version must be 4.0")
        return errors
    design = experiment.get("design", {})
    if design.get("type") != "taxonomy_balanced_v1":
        errors.append("experiment design.type must be taxonomy_balanced_v1")
    if design.get("manipulated_claims") != policy.get("main_levels", {}).get("claims"):
        errors.append("experiment manipulated claims do not match context policy")
    if design.get("locations") != policy.get("main_levels", {}).get("locations"):
        errors.append("experiment locations do not match context policy")
    if design.get("methods") != policy.get("main_levels", {}).get("methods"):
        errors.append("experiment methods do not match context policy")
    semantic_contract = experiment.get("semantic_contract", {})
    if semantic_contract.get("version") != policy.get("semantic_contract_version"):
        errors.append("experiment semantic contract version does not match context policy")
    for flag in (
        "claim_content_mode_is_explicit",
        "presentation_attributes_are_separate_from_claim_semantics",
        "carrier_family_is_separate_from_document_role",
        "truthfulness_and_rule_authority_are_not_interchangeable",
        "neutral_control_must_not_contain_grounding_guidance"
    ):
        if semantic_contract.get(flag) is not True:
            errors.append(f"experiment semantic contract must enable {flag}")
    analysis_sets = experiment.get("analysis_sets", {})
    eligible_claims = sorted(
        claim_id
        for claim_id, claim in policy.get("claim_categories", {}).items()
        if claim.get("primary_analysis_eligible") is True
    )
    pending_claims = sorted(
        claim_id
        for claim_id, claim in policy.get("claim_categories", {}).items()
        if claim.get("primary_analysis_eligible") is False
    )
    if sorted(analysis_sets.get("primary_claims", [])) != eligible_claims:
        errors.append("experiment primary claims do not match policy eligibility labels")
    if sorted(analysis_sets.get("pending_reference_evidence", [])) != pending_claims:
        errors.append("experiment pending claims do not match policy eligibility labels")
    if set(experiment.get("conditions", [])) != {"clean", "benign", "manipulated"}:
        errors.append("experiment conditions must be clean, benign, manipulated")
    if experiment.get("repeats", 0) < 1:
        errors.append("repeats must be >= 1")
    if not agents:
        errors.append("agents must be non-empty")
    agent_ids = [agent.get("agent_id") for agent in agents]
    if len(set(agent_ids)) != len(agent_ids):
        errors.append("duplicate agent IDs")
    if experiment.get("pairing", {}).get("baseline") != "clean":
        errors.append("pairing baseline must be clean")
    if experiment.get("pairing", {}).get("control") != "benign":
        errors.append("pairing control must be benign")
    if experiment.get("pairing", {}).get("treatments") != ["manipulated"]:
        errors.append("pairing treatment must be manipulated")
    for key, value in experiment.get("invariance", {}).items():
        if value is not True:
            errors.append(f"invariance.{key} must be true")

    expected_agents = policy.get("allocation", {}).get("main_design", {}).get("agent_count")
    if expected_agents is not None and len(agents) != expected_agents:
        errors.append(f"allocation expects {expected_agents} agents, found {len(agents)}")
    expected_repeats = policy.get("allocation", {}).get("main_design", {}).get("repeat_count")
    if expected_repeats is not None and experiment.get("repeats") != expected_repeats:
        errors.append(f"allocation expects {expected_repeats} repeats")
    return errors


def validate_run_plan(plan, experiment, policy, projects, agents):
    errors = []
    if plan.get("schema_version") != "4.0":
        errors.append("run-plan schema_version must be 4.0")
        return errors
    if plan.get("experiment_id") != experiment.get("experiment_id"):
        errors.append("run-plan experiment_id mismatch")
    if plan.get("design_type") != experiment.get("design", {}).get("type"):
        errors.append("run-plan design type mismatch")

    runs = plan.get("runs", [])
    expected_runs = len(projects) * len(agents) * experiment["repeats"] * (
        2 + len(experiment["design"]["manipulated_claims"])
    )
    if len(runs) != expected_runs:
        errors.append(f"run-plan expected {expected_runs} runs, found {len(runs)}")
    run_ids = [run.get("run_id") for run in runs]
    if len(set(run_ids)) != len(run_ids):
        errors.append("run plan has duplicate run IDs")

    conditions = Counter(run.get("condition") for run in runs)
    expected_conditions = {
        "clean": len(projects) * len(agents) * experiment["repeats"],
        "benign": len(projects) * len(agents) * experiment["repeats"],
        "manipulated": (
            len(projects) * len(agents) * experiment["repeats"]
            * len(experiment["design"]["manipulated_claims"])
        )
    }
    if dict(conditions) != expected_conditions:
        errors.append(f"run-plan condition counts mismatch: {dict(conditions)}")

    claims = experiment["design"]["manipulated_claims"]
    locations = experiment["design"]["locations"]
    methods = experiment["design"]["methods"]
    agent_ids = [agent["agent_id"] for agent in agents]
    groups = defaultdict(list)
    by_run_id = {run.get("run_id"): run for run in runs}

    for run in runs:
        required = {
            "run_id", "project_id", "repository", "cve", "condition", "agent_id",
            "scaffold", "model", "agent_config", "run", "timeout_s", "audit_task",
            "context_policy", "workspace_dir", "artifact_dir", "pair_key",
            "snapshot_archive", "snapshot_sha256", "claim", "claim_category",
            "location", "method", "carrier", "truthfulness", "verifiability",
            "context_variant_id"
        }
        missing = required - set(run)
        if missing:
            errors.append(f"{run.get('run_id', '<missing>')}: missing fields {sorted(missing)}")
            continue
        if run["condition"] == "clean":
            if any(run[field] is not None for field in ("claim", "claim_category", "location", "method", "carrier")):
                errors.append(f"{run['run_id']}: clean run has taxonomy fields")
        elif run["condition"] == "benign":
            if run["claim"] is not None or run["method"] is not None or run["claim_category"] is not None:
                errors.append(f"{run['run_id']}: benign run has claim or method fields")
            if run["location"] not in locations:
                errors.append(f"{run['run_id']}: invalid benign location")
            elif run["carrier"] != policy["locations"][run["location"]]["carrier"]:
                errors.append(f"{run['run_id']}: benign carrier mismatch")
        elif run["condition"] == "manipulated":
            if run["claim"] not in claims:
                errors.append(f"{run['run_id']}: invalid claim")
            if run["location"] not in locations:
                errors.append(f"{run['run_id']}: invalid location")
            if run["method"] not in methods:
                errors.append(f"{run['run_id']}: invalid method")
            claim = policy["claim_categories"].get(run["claim"], {})
            location = policy["locations"].get(run["location"], {})
            if run["claim_category"] != claim.get("name"):
                errors.append(f"{run['run_id']}: claim category mismatch")
            if run["carrier"] != location.get("carrier"):
                errors.append(f"{run['run_id']}: carrier mismatch")
            if run["truthfulness"] != claim.get("truthfulness"):
                errors.append(f"{run['run_id']}: truthfulness mismatch")
            if run["verifiability"] != claim.get("verifiability"):
                errors.append(f"{run['run_id']}: verifiability mismatch")
        else:
            errors.append(f"{run['run_id']}: invalid condition")
        groups[(run["project_id"], run["agent_id"], run["run"])].append(run)

    project_ids = {card["project_id"] for card in projects}
    for key, group in groups.items():
        project_id, agent_id, repeat = key
        if project_id not in project_ids or agent_id not in agent_ids or repeat not in range(1, experiment["repeats"] + 1):
            errors.append(f"invalid pair group: {key}")
            continue
        group_conditions = Counter(run["condition"] for run in group)
        if group_conditions.get("clean", 0) != 1 or group_conditions.get("benign", 0) != 1:
            errors.append(f"{key}: expected exactly one clean and one benign run")
        manipulated = [run for run in group if run["condition"] == "manipulated"]
        if Counter(run["claim"] for run in manipulated) != Counter(claims):
            errors.append(f"{key}: manipulated claims are incomplete or duplicated")

        clean = next((run for run in group if run["condition"] == "clean"), None)
        benign = next((run for run in group if run["condition"] == "benign"), None)
        if clean and benign:
            if any(run.get("baseline_run_id") != clean["run_id"] for run in group if run["condition"] != "clean"):
                errors.append(f"{key}: baseline run ID mismatch")
            if any(run.get("control_run_id") != benign["run_id"] for run in manipulated):
                errors.append(f"{key}: control run ID mismatch")
            if len({run["snapshot_sha256"] for run in group}) != 1:
                errors.append(f"{key}: snapshot hash differs across paired conditions")
            agent_index = agent_ids.index(agent_id)
            cell_index = agent_index * experiment["repeats"] + (repeat - 1)
            expected_benign_location = locations[cell_index % len(locations)]
            if benign["location"] != expected_benign_location:
                errors.append(f"{key}: benign location allocation mismatch")
            for run in manipulated:
                claim_index = claims.index(run["claim"])
                pair_index = (claim_index + cell_index) % (len(locations) * len(methods))
                expected_location = locations[pair_index // len(methods)]
                expected_method = methods[pair_index % len(methods)]
                if run["location"] != expected_location or run["method"] != expected_method:
                    errors.append(f"{run['run_id']}: WHERE/HOW allocation mismatch")
        for run_id in [run.get("baseline_run_id") for run in group if run.get("baseline_run_id")] + [run.get("control_run_id") for run in group if run.get("control_run_id")]:
            if run_id not in by_run_id:
                errors.append(f"{key}: referenced run missing: {run_id}")

    # Balance checks are per repository, avoiding repository-level confounding.
    for project_id in project_ids:
        project_runs = [run for run in runs if run["project_id"] == project_id]
        manipulated_runs = [run for run in project_runs if run["condition"] == "manipulated"]
        pair_counts = Counter((run["location"], run["method"]) for run in manipulated_runs)
        if set(pair_counts) != set((location, method) for location in locations for method in methods):
            errors.append(f"{project_id}: WHERE × HOW grid is incomplete")
        elif min(pair_counts.values()) < 5 or max(pair_counts.values()) > 6:
            errors.append(f"{project_id}: WHERE × HOW counts are outside 5–6")

        for claim in claims:
            claim_runs = [run for run in manipulated_runs if run["claim"] == claim]
            location_counts = Counter(run["location"] for run in claim_runs)
            method_counts = Counter(run["method"] for run in claim_runs)
            if set(location_counts) != set(locations) or set(method_counts) != set(methods):
                errors.append(f"{project_id}/{claim}: WHERE or HOW coverage is incomplete")
            elif min(location_counts.values()) < 3 or max(location_counts.values()) > 4:
                errors.append(f"{project_id}/{claim}: WHERE counts are outside 3–4")
            elif min(method_counts.values()) < 3 or max(method_counts.values()) > 4:
                errors.append(f"{project_id}/{claim}: HOW counts are outside 3–4")

        benign_locations = Counter(
            run["location"] for run in project_runs if run["condition"] == "benign"
        )
        if set(benign_locations) != set(locations):
            errors.append(f"{project_id}: benign location coverage is incomplete")
        elif min(benign_locations.values()) < 3 or max(benign_locations.values()) > 4:
            errors.append(f"{project_id}: benign location counts are outside 3–4")

    return errors


def validate_runtimeContracts(experiment_path, experiment, agents):
    errors = []
    audit_task = experiment_path.parent / experiment.get("audit_task", "")
    if not audit_task.is_file():
        errors.append(f"audit task not found: {audit_task}")
    for agent in agents:
        agent_id = agent.get("agent_id", "<missing>")
        agent_dir = experiment_path.parent / "agents" / agent_id
        runtime_path = agent_dir / agent.get("runtime_file", "")
        if not runtime_path.is_file():
            errors.append(f"{agent_id}: runtime file not found: {runtime_path}")
            continue
        runtime = load_json(runtime_path)
        program = runtime.get("program")
        if not isinstance(program, str) or not program:
            errors.append(f"{agent_id}: runtime program must be a non-empty string")
        elif Path(program).is_absolute() or program.startswith(("\\", "/")):
            errors.append(f"{agent_id}: runtime program must be resolved from PATH")
        if not isinstance(runtime.get("arguments"), list):
            errors.append(f"{agent_id}: runtime arguments must be a list")
        else:
            for argument in runtime["arguments"]:
                if not isinstance(argument, str):
                    errors.append(f"{agent_id}: runtime arguments must be strings")
                    break
                placeholders = set(re.findall(r"\{[^}]+\}", argument))
                invalid = placeholders - ALLOWED_RUNTIME_PLACEHOLDERS
                if invalid:
                    errors.append(f"{agent_id}: invalid runtime placeholders {sorted(invalid)}")
        if runtime.get("stdin") not in ("prompt", "none"):
            errors.append(f"{agent_id}: runtime stdin must be prompt or none")
        if runtime.get("cwd") not in ("{workspace}", "{artifact_dir}"):
            errors.append(f"{agent_id}: runtime cwd must be {{workspace}} or {{artifact_dir}}")
        for field in ("stdout", "stderr"):
            value = runtime.get(field)
            if not isinstance(value, str) or not value or ".." in Path(value).parts:
                errors.append(f"{agent_id}: runtime {field} must be a safe relative path")
        if agent.get("config_template"):
            template = agent_dir / agent["config_template"]
            if not template.is_file():
                errors.append(f"{agent_id}: config template not found: {template}")
        if runtime.get("workspace_config_file"):
            value = runtime["workspace_config_file"]
            if not isinstance(value, str) or not value or ".." in Path(value).parts:
                errors.append(f"{agent_id}: workspace_config_file must be a safe relative path")
    return errors


def validate(args):
    benchmark_path = Path(args.benchmark).resolve()
    experiment_path = Path(args.experiment).resolve()
    policy_path = Path(args.context_policy).resolve()
    manifest, projects = load_benchmark(benchmark_path)
    experiment = load_json(experiment_path)
    policy = load_json(policy_path)
    agents = load_agents(experiment_path, experiment)

    errors = []
    warnings = []
    policy_errors, claim_names = validate_context_policy(policy)
    errors.extend(policy_errors)
    errors.extend(validate_experiment(experiment, policy, agents, len(projects)))
    errors.extend(validate_runtimeContracts(experiment_path, experiment, agents))

    project_ids = [card.get("project_id") for card in projects]
    repositories = [card.get("repository") for card in projects]
    cves = [card.get("vulnerability", {}).get("cve") for card in projects]
    if len(projects) != 20:
        errors.append(f"expected 20 projects, found {len(projects)}")
    if len(set(project_ids)) != len(project_ids):
        errors.append("duplicate project IDs")
    if len(set(repositories)) != len(repositories):
        errors.append("duplicate repositories")
    if len(set(cves)) != len(cves):
        errors.append("duplicate CVEs")
    if manifest.get("schema_version") != "3.0":
        errors.append("benchmark schema_version must be 3.0")
    if manifest.get("primary_cve_policy") != "one_cve_per_repository":
        errors.append("primary CVE policy must be one_cve_per_repository")
    if claim_names != set(manifest.get("claim_categories", [])):
        errors.append("context-policy claim names do not match benchmark manifest")

    provisional_count = 0
    for card in projects:
        project_id = card.get("project_id", "<missing>")
        vulnerability = card.get("vulnerability", {})
        context_claim = card.get("context_claim", {})
        snapshot = card.get("snapshot", {})
        if card.get("schema_version") != "3.0":
            errors.append(f"{project_id}: card schema_version must be 3.0")
        if not card.get("primary_experiment"):
            errors.append(f"{project_id}: primary_experiment must be true")
        if vulnerability.get("severity") not in (3, 4):
            errors.append(f"{project_id}: severity must be 3 or 4")
        if not isinstance(vulnerability.get("cvss"), (int, float)):
            errors.append(f"{project_id}: CVSS must be numeric")
        elif not 7.0 <= vulnerability["cvss"] <= 10.0:
            errors.append(f"{project_id}: CVSS must be between 7.0 and 10.0")
        if context_claim.get("category") not in claim_names:
            errors.append(f"{project_id}: unknown claim category {context_claim.get('category')}")
        if not isinstance(context_claim.get("target_areas"), list) or not context_claim.get("target_areas"):
            errors.append(f"{project_id}: context target_areas must be a non-empty list")
        missing_snapshot = [
            field for field in REQUIRED_SNAPSHOT_FIELDS
            if field not in snapshot or snapshot[field] in (None, "")
        ]
        if missing_snapshot:
            errors.append(f"{project_id}: missing snapshot fields {missing_snapshot}")
        if snapshot.get("immutability") != "sha256_snapshot_lock":
            errors.append(f"{project_id}: snapshot immutability must be sha256_snapshot_lock")
        errors.extend(
            validate_zip(
                project_id,
                snapshot_path(benchmark_path, manifest, card),
                snapshot.get("root_directory")
            )
        )

        status = card.get("ground_truth_status")
        if status not in ("provisional", "frozen"):
            errors.append(f"{project_id}: ground_truth_status must be provisional or frozen")
        elif status == "frozen":
            ground_truth = card.get("ground_truth", {})
            missing_ground_truth = [
                field for field in REQUIRED_GROUND_TRUTH_FIELDS
                if field not in ground_truth or ground_truth[field] in (None, "", [], {})
            ]
            if missing_ground_truth:
                errors.append(f"{project_id}: frozen card missing ground truth fields {missing_ground_truth}")
        else:
            provisional_count += 1
            if args.strict_ground_truth:
                errors.append(f"{project_id}: ground truth is not frozen")

    lock_path = benchmark_path.parent / manifest.get("snapshot_lock", "")
    if lock_path.is_file():
        lock = load_json(lock_path)
        locked = {item.get("project_id"): item.get("sha256") for item in lock.get("snapshots", [])}
        if set(locked) != set(project_ids):
            errors.append("snapshot lock project IDs do not match benchmark manifest")
        for card in projects:
            path = snapshot_path(benchmark_path, manifest, card)
            if path.is_file() and locked.get(card["project_id"]) != sha256(path):
                errors.append(f"{card['project_id']}: snapshot SHA-256 does not match lock")
    else:
        warnings.append("snapshot lock not found; run freeze_snapshots.py before main runs")

    if args.run_plan:
        run_plan_path = Path(args.run_plan).resolve()
        if not run_plan_path.is_file():
            errors.append(f"run plan not found: {run_plan_path}")
        else:
            plan = load_json(run_plan_path)
            errors.extend(validate_run_plan(plan, experiment, policy, projects, agents))

    if args.compute_hashes:
        print("Snapshot hashes:")
        for card in projects:
            path = snapshot_path(benchmark_path, manifest, card)
            if path.is_file():
                print(f"  {card['project_id']} {sha256(path)}")

    planned_runs = len(projects) * len(agents) * experiment.get("repeats", 0) * (
        2 + len(experiment.get("design", {}).get("manipulated_claims", []))
    )
    print(f"Benchmark: {manifest.get('benchmark_id')}")
    print(f"Experiment: {experiment.get('experiment_id')}")
    print(f"Projects: {len(projects)}")
    print(f"Provisional ground-truth cards: {provisional_count}")
    print(f"Conditions: {experiment.get('conditions')}")
    print(f"Agents: {len(agents)}")
    print(f"Repeats: {experiment.get('repeats')}")
    print(f"Planned runs: {planned_runs}")
    if args.run_plan:
        print(f"Run plan: {Path(args.run_plan).resolve()}")
    if warnings:
        print("Warnings:")
        for warning in warnings:
            print(f"  {warning}")
    if errors:
        print("Errors:")
        for error in errors:
            print(f"  {error}")
        raise SystemExit(1)
    print("Validation: OK")


def main():
    parser = argparse.ArgumentParser(
        description="Validate the S2 benchmark, taxonomy policy, experiment, and run plan"
    )
    parser.add_argument("--benchmark", required=True)
    parser.add_argument("--experiment", required=True)
    parser.add_argument("--context-policy", required=True)
    parser.add_argument("--run-plan")
    parser.add_argument("--strict-ground-truth", action="store_true")
    parser.add_argument("--compute-hashes", action="store_true")
    validate(parser.parse_args())


if __name__ == "__main__":
    main()
