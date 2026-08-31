from __future__ import annotations

import hashlib
import ipaddress
import re
from collections import Counter, defaultdict

from .config import policy_items
from .models import Rule, SourceRecord, SourceResult
from .normalize import covered_by_suffix, structural_random_reasons

TYPE_ORDER = {"HOST": 1, "HOST-SUFFIX": 2, "HOST-KEYWORD": 3, "IP-CIDR": 4, "IP6-CIDR": 5, "GEOIP": 6, "USER-AGENT": 7}


def _matches(value: str, item) -> bool:
    return value == item.value if item.match == "exact" else value == item.value or value.endswith("." + item.value)


def _items_for_profile(policy: dict, profile: str):
    return [item for item in policy_items(policy, "domain_evidence_catalog") if profile in next(raw["profiles"] for raw in policy["domain_evidence_catalog"] if raw["id"] == item.item_id)]


def _dedupe_records(results: list[SourceResult]) -> dict[Rule, list[SourceRecord]]:
    grouped: dict[Rule, list[SourceRecord]] = defaultdict(list)
    consensus_sources = {result.source.source_id for result in results if result.source.participates_in_consensus}
    for result in results:
        for record in result.records:
            if record.rule:
                grouped[record.rule].append(record)
    for records in grouped.values():
        consensus = sorted({record.source for record in records} & consensus_sources)
        for record in records:
            record.consensus_sources = consensus
    return grouped


def _is_dns(records: list[SourceRecord], sources: dict) -> bool:
    return any(sources[record.source].role == "dns_bypass" for record in records)


def _label_tokens(rule: Rule, tokens: set[str], patterns: list[re.Pattern]) -> list[str]:
    if rule.rule_type not in {"HOST", "HOST-SUFFIX"}:
        return []
    return sorted(label for label in set(rule.value.split(".")) if label in tokens or any(pattern.fullmatch(label) for pattern in patterns))


def _catalog_matches(rule: Rule, items) -> list[str]:
    if rule.rule_type not in {"HOST", "HOST-SUFFIX"}:
        return []
    return [item.item_id for item in items if _matches(rule.value, item)]


def _random_reasons(rule: Rule, policy: dict) -> list[str]:
    return structural_random_reasons(rule.value, policy["random_domain_policy"]) if rule.rule_type in {"HOST", "HOST-SUFFIX"} else []


def _cidr_reduce(rules: set[Rule], reserved: set[Rule]) -> set[Rule]:
    result = set(rules)
    for rule in sorted(rules, key=lambda r: (r.rule_type, r.value, tuple(sorted(r.modifiers)))):
        if rule.rule_type not in {"IP-CIDR", "IP6-CIDR"} or rule in reserved:
            continue
        network = ipaddress.ip_network(rule.value)
        for parent in result:
            if parent is rule or parent.rule_type != rule.rule_type or parent.modifiers != rule.modifiers:
                continue
            if network.subnet_of(ipaddress.ip_network(parent.value)) and network != ipaddress.ip_network(parent.value):
                result.discard(rule)
                break
    # Exact CIDR conflicts: prefer no-resolve, except a reserved variant always remains.
    for rule in list(result):
        if rule.rule_type not in {"IP-CIDR", "IP6-CIDR"} or rule in reserved:
            continue
        preferred = Rule(rule.rule_type, rule.value, frozenset({"no-resolve"}))
        if preferred in result and "no-resolve" not in rule.modifiers and preferred not in reserved:
            result.discard(rule)
    return result


def _suffix_reduce(rules: set[Rule], reserved: set[Rule]) -> tuple[set[Rule], dict[Rule, str]]:
    suffixes = {rule.value for rule in rules if rule.rule_type == "HOST-SUFFIX"}
    result = set(rules)
    covered: dict[Rule, str] = {}
    for rule in sorted(rules, key=lambda r: (TYPE_ORDER.get(r.rule_type, 99), r.value)):
        if rule in reserved or rule.rule_type not in {"HOST", "HOST-SUFFIX"}:
            continue
        candidate_suffixes = suffixes - ({rule.value} if rule.rule_type == "HOST-SUFFIX" else set())
        cover = covered_by_suffix(rule.value, candidate_suffixes)
        if cover:
            result.discard(rule)
            covered[rule] = cover
    return result, covered


def _select_profile(name: str, grouped: dict[Rule, list[SourceRecord]], sources: dict, policy: dict) -> tuple[list[Rule], dict[Rule, str], dict[str, int]]:
    limit = policy["profile_limits"][name]
    catalog = _items_for_profile(policy, name)
    keyword_items = policy_items(policy, "keyword_allowlist")
    geo_ok = {str(value).upper() for value in policy.get("mobile_geoip_allowlist", [])}
    tokens = set(policy.get("admission_label_tokens", []))
    patterns = [re.compile(pattern) for pattern in policy.get("admission_label_patterns", [])]
    reserved: set[Rule] = set()
    ranked: list[tuple[tuple, Rule]] = []
    reasons: dict[Rule, str] = {}
    funnel: Counter[str] = Counter()

    for rule, records in grouped.items():
        dns = _is_dns(records, sources)
        consensus = len(records[0].consensus_sources) >= 2
        random = _random_reasons(rule, policy)
        matched_catalog = _catalog_matches(rule, catalog)
        labels = _label_tokens(rule, tokens, patterns)
        keyword = rule.rule_type in {"HOST-KEYWORD", "USER-AGENT"} and any(rule.value == item.value for item in keyword_items)
        geo = rule.rule_type == "GEOIP" and rule.value in geo_ok
        if dns and rule.rule_type in {"HOST", "HOST-SUFFIX", "IP-CIDR", "IP6-CIDR"}:
            reserved.add(rule)
            reasons[rule] = "dns_passthrough_reserved"
            funnel["dns_passthrough"] += 1
            continue
        if random and not (matched_catalog or consensus):
            reasons[rule] = "structural_random_unexceptioned:" + ",".join(random)
            funnel["structural_random"] += 1
            continue
        if rule.rule_type in {"IP-CIDR", "IP6-CIDR"}:
            eligible = consensus or bool(matched_catalog)
        elif rule.rule_type == "GEOIP":
            eligible = geo
        elif rule.rule_type in {"HOST-KEYWORD", "USER-AGENT"}:
            eligible = keyword
        else:
            # Label categories are full DNS-label matches (never arbitrary substrings).
            # They provide the aggressive-but-bounded QX/DNS complement the profiles need.
            eligible = bool(matched_catalog or consensus or labels)
        if not eligible:
            reasons[rule] = "no_catalog_consensus_or_label_category"
            funnel["no_evidence"] += 1
            continue
        strength = 4 if matched_catalog else 3 if consensus else 2 if labels else 1
        specificity = max((item.match == "exact" for item in catalog if item.item_id in matched_catalog), default=False)
        score = (-strength, -int(specificity), -len(labels), TYPE_ORDER[rule.rule_type], rule.value, tuple(sorted(rule.modifiers)))
        ranked.append((score, rule))
        reasons[rule] = "catalog:" + ",".join(matched_catalog) if matched_catalog else "consensus" if consensus else "label_category:" + ",".join(labels)
        funnel["eligible"] += 1

    if len(reserved) > limit:
        raise ValueError(f"{name}: DNS passthrough reserves {len(reserved)} rules above limit {limit}")
    selected = set(reserved)
    for _, rule in sorted(ranked):
        if len(selected) >= limit:
            reasons[rule] = "profile_cap_exhausted"
            funnel["cap_exhausted"] += 1
            continue
        selected.add(rule)
    selected = _cidr_reduce(selected, reserved)
    selected, covered = _suffix_reduce(selected, reserved)
    for rule, suffix in covered.items():
        reasons[rule] = "covered_by_selected_native_suffix:" + suffix
        funnel["covered"] += 1
    funnel["reserved"] = len(reserved)
    funnel["selected"] = len(selected)
    return sorted(selected, key=lambda r: (TYPE_ORDER[r.rule_type], r.value, tuple(sorted(r.modifiers)))), reasons, dict(funnel)


def build_profiles(results: list[SourceResult], policy: dict) -> tuple[dict[str, list[Rule]], dict[Rule, tuple[str, str | None]]]:
    grouped = _dedupe_records(results)
    sources = {result.source.source_id: result.source for result in results}
    profiles: dict[str, list[Rule]] = {}
    profile_reasons: dict[str, dict[Rule, str]] = {}
    for name in ("mac", "mobile", "lite"):
        profiles[name], profile_reasons[name], _ = _select_profile(name, grouped, sources, policy)
    final_sets = {name: set(rules) for name, rules in profiles.items()}
    decisions: dict[Rule, tuple[str, str | None]] = {}
    for rule, records in grouped.items():
        for record in records:
            for name, output_name in (("mac", "stable"), ("mobile", "mobile_stable"), ("lite", "lite")):
                reason = profile_reasons[name].get(rule, "not_selected")
                record.decisions[output_name] = "kept" if rule in final_sets[name] else reason
                if reason.startswith("covered_by_selected_native_suffix"):
                    record.covered_by = reason.split(":", 1)[1]
            if rule not in final_sets["mac"]:
                decisions[rule] = ("dropped", profile_reasons["mac"].get(rule))
            else:
                decisions[rule] = ("kept", None)
    return profiles, decisions


def profile_summary(results: list[SourceResult], profiles: dict[str, list[Rule]], policy: dict) -> dict:
    grouped = _dedupe_records(results)
    sources = {result.source.source_id: result.source for result in results}
    summaries = {}
    for name in ("mac", "mobile", "lite"):
        _, _, funnel = _select_profile(name, grouped, sources, policy)
        summaries[name] = funnel | {"limit": policy["profile_limits"][name]}
    return summaries
