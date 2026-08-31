from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .models import SourceConfig


class ConfigurationError(ValueError):
    pass


@dataclass(frozen=True)
class PolicyItem:
    item_id: str
    value: str
    match: str
    category: str
    note: str
    evidence: str


@dataclass(frozen=True)
class AppConfig:
    policy: dict[str, Any]
    sources: tuple[SourceConfig, ...]
    policy_hash: str
    sources_hash: str


def file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigurationError(f"Invalid JSON in {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ConfigurationError(f"{path} must contain a JSON object")
    return data


def _positive_int(data: dict[str, Any], key: str) -> int:
    value = data.get(key)
    if not isinstance(value, int) or value <= 0:
        raise ConfigurationError(f"{key} must be a positive integer")
    return value


def _validate_policy_item(item: dict[str, Any], allow_match: bool) -> None:
    for key in ("id", "value", "category", "note", "evidence"):
        if not isinstance(item.get(key), str) or not item[key].strip():
            raise ConfigurationError(f"Policy item requires non-empty {key}")
    if allow_match and item.get("match") not in {"exact", "suffix"}:
        raise ConfigurationError("Lite allowlist items require match=exact or suffix")


def load_config(root: Path) -> AppConfig:
    scripts = root / "scripts"
    policy_path = scripts / "rule_policy.json"
    sources_path = scripts / "sources.json"
    policy = _load_json(policy_path)
    source_data = _load_json(sources_path)
    _positive_int(policy, "policy_version")
    _positive_int(source_data, "sources_version")
    if not isinstance(policy.get("qx_policy"), str) or not policy["qx_policy"]:
        raise ConfigurationError("qx_policy is required")
    limits = policy.get("profile_limits")
    expected_profiles = {"clash_full", "qx_universal", "qx_compact"}
    if not isinstance(limits, dict) or set(limits) != expected_profiles:
        raise ConfigurationError("profile_limits must define clash_full/qx_universal/qx_compact")
    for name, limit in limits.items():
        if not isinstance(limit, dict) or not isinstance(limit.get("target"), int) or not isinstance(limit.get("max"), int) or limit["target"] <= 0 or limit["max"] <= 0 or limit["target"] > limit["max"]:
            raise ConfigurationError(f"profile_limits.{name} requires positive target <= max")
    random_policy = policy.get("random_domain_policy")
    if not isinstance(random_policy, dict) or any(not isinstance(value, (int, float)) or value <= 0 for value in random_policy.values()):
        raise ConfigurationError("random_domain_policy must contain positive thresholds")
    for key in ("web_label_categories", "mobile_sdk_labels"):
        values = policy.get(key)
        if not isinstance(values, list) or not values or not all(isinstance(value, str) and value for value in values):
            raise ConfigurationError(f"{key} must be a non-empty string list")
    seen_ids: set[str] = set()
    for item in policy.get("domain_evidence_catalog", []):
        _validate_policy_item(item, True)
        platforms = item.get("platforms")
        if not isinstance(platforms, list) or not platforms or not set(platforms) <= {"web", "mobile", "shared"}:
            raise ConfigurationError("Catalog items require platforms from web/mobile/shared")
        if not isinstance(item.get("lite_enabled"), bool):
            raise ConfigurationError("Catalog items require lite_enabled boolean")
        if item["id"] in seen_ids:
            raise ConfigurationError(f"Duplicate policy ID {item['id']}")
        seen_ids.add(item["id"])
    for item in policy.get("keyword_allowlist", []):
        _validate_policy_item(item, False)
        if item["id"] in seen_ids:
            raise ConfigurationError(f"Duplicate policy ID {item['id']}")
        seen_ids.add(item["id"])
    guards = policy.get("release_guards")
    if not isinstance(guards, dict):
        raise ConfigurationError("release_guards is required")
    for key in ("output_total_change_pct", "source_parsed_change_pct", "safety_rejection_change_pct", "max_rejection_rate_pct"):
        value = guards.get(key)
        if not isinstance(value, (int, float)) or value < 0 or value > 100:
            raise ConfigurationError(f"release_guards.{key} must be 0..100")

    sources: list[SourceConfig] = []
    source_ids: set[str] = set()
    raw_sources = source_data.get("sources")
    if not isinstance(raw_sources, list) or not raw_sources:
        raise ConfigurationError("sources must be a non-empty list")
    for item in raw_sources:
        required = ("id", "url", "role", "tier", "allowed_hosts", "max_bytes", "max_rules")
        if not isinstance(item, dict) or any(key not in item for key in required):
            raise ConfigurationError("Each source has missing fields")
        if item["id"] in source_ids or not isinstance(item["id"], str):
            raise ConfigurationError(f"Duplicate/invalid source ID {item.get('id')}")
        if not isinstance(item["url"], str) or not item["url"].startswith("https://"):
            raise ConfigurationError(f"Source {item['id']} must use HTTPS")
        if not isinstance(item["allowed_hosts"], list) or not all(isinstance(host, str) and host for host in item["allowed_hosts"]):
            raise ConfigurationError(f"Source {item['id']} has invalid allowed_hosts")
        if not isinstance(item.get("participates_in_consensus"), bool):
            raise ConfigurationError(f"Source {item['id']} needs participates_in_consensus")
        if not isinstance(item["max_bytes"], int) or item["max_bytes"] <= 0 or not isinstance(item["max_rules"], int) or item["max_rules"] <= 0:
            raise ConfigurationError(f"Source {item['id']} has invalid limits")
        source_ids.add(item["id"])
        sources.append(SourceConfig(item["id"], item["url"], item["role"], item["tier"], item["participates_in_consensus"], tuple(item["allowed_hosts"]), item["max_bytes"], item["max_rules"]))
    return AppConfig(policy, tuple(sources), file_sha256(policy_path), file_sha256(sources_path))


def policy_items(policy: dict[str, Any], key: str) -> tuple[PolicyItem, ...]:
    return tuple(PolicyItem(item["id"], item["value"].lower(), item.get("match", "exact"), item["category"], item["note"], item["evidence"]) for item in policy.get(key, []))
