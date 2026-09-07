#!/usr/bin/env python3
import hashlib
import json
from pathlib import Path


def load_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def sha256(path, block_size=1024 * 1024):
    digest = hashlib.sha256()
    with open(path, "rb") as source:
        while True:
            block = source.read(block_size)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


def load_benchmark(benchmark_path):
    benchmark_path = Path(benchmark_path).resolve()
    manifest = load_json(benchmark_path)
    projects_dir = (benchmark_path.parent / manifest["projects_dir"]).resolve()
    pattern = manifest.get("project_card_pattern", "{project_id}.json")

    cards = []
    for project_id in manifest["project_ids"]:
        card_path = projects_dir / pattern.format(project_id=project_id)
        if not card_path.is_file():
            raise FileNotFoundError(f"project card not found: {card_path}")
        card = load_json(card_path)
        if card.get("project_id") != project_id:
            raise ValueError(f"project ID mismatch in {card_path}")
        cards.append(card)
    return manifest, cards


def snapshot_path(benchmark_path, manifest, card):
    benchmark_path = Path(benchmark_path).resolve()
    root = (benchmark_path.parent / manifest["snapshot_root"]).resolve()
    return root / card["snapshot"]["archive"]


def load_agents(experiment_path, experiment):
    experiment_path = Path(experiment_path).resolve()
    experiment_dir = experiment_path.parent
    agents = []
    for item in experiment["agents"]:
        if "agent_config" in item:
            agent_path = (experiment_dir / item["agent_config"]).resolve()
            if not agent_path.is_file():
                raise FileNotFoundError(f"agent config not found: {agent_path}")
            agent = load_json(agent_path)
            if not {"agent_id", "scaffold", "model"}.issubset(agent):
                raise ValueError(f"incomplete agent config: {agent_path}")
            agents.append(agent)
        elif {"agent_id", "scaffold", "model"}.issubset(item):
            agents.append(item)
        else:
            raise ValueError(f"incomplete agent entry: {item}")
    return agents
