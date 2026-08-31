from __future__ import annotations

import ipaddress
from collections import defaultdict

from .config import policy_items
from .models import Rule, SourceRecord, SourceResult
from .normalize import covered_by_suffix, structural_random_reasons

TYPE_ORDER = {"HOST": 1, "HOST-SUFFIX": 2, "HOST-KEYWORD": 3, "IP-CIDR": 4, "IP6-CIDR": 5, "GEOIP": 6, "USER-AGENT": 7}
PROFILES = ("clash_full", "qx_universal", "qx_compact")


def _matches(value, item):
    return value == item.value if item.match == "exact" else value == item.value or value.endswith("." + item.value)


def _group(results):
    grouped = defaultdict(list)
    consensus = {x.source.source_id for x in results if x.source.participates_in_consensus}
    for result in results:
        for record in result.records:
            if record.rule:
                grouped[record.rule].append(record)
    for records in grouped.values():
        sources = sorted({r.source for r in records} & consensus)
        for record in records:
            record.consensus_sources = sources
    return grouped


def _reduce(rules, reserved):
    result = set(rules)
    suffixes = {r.value for r in result if r.rule_type == "HOST-SUFFIX"}
    for rule in sorted(result, key=lambda r: (TYPE_ORDER[r.rule_type], r.value)):
        if rule in reserved or rule.rule_type not in {"HOST", "HOST-SUFFIX"}:
            continue
        cover = covered_by_suffix(rule.value, suffixes - ({rule.value} if rule.rule_type == "HOST-SUFFIX" else set()))
        if cover:
            result.discard(rule)
    for rule in sorted(list(result), key=lambda r: (r.rule_type, r.value, tuple(r.modifiers))):
        if rule in reserved or rule.rule_type not in {"IP-CIDR", "IP6-CIDR"}:
            continue
        net = ipaddress.ip_network(rule.value)
        for parent in result:
            if parent is rule or parent.rule_type != rule.rule_type or parent.modifiers != rule.modifiers:
                continue
            if net != ipaddress.ip_network(parent.value) and net.subnet_of(ipaddress.ip_network(parent.value)):
                result.discard(rule); break
    return result


def _catalog_data(rule, raw_catalog):
    matched = []
    for item in raw_catalog:
        if rule.rule_type in {"HOST", "HOST-SUFFIX"} and (rule.value == item["value"] or item["match"] == "suffix" and rule.value.endswith("." + item["value"])):
            matched.append(item)
    platforms = set().union(*(set(x["platforms"]) for x in matched)) if matched else set()
    return matched, platforms, any(x["lite_enabled"] for x in matched)


def _select(name, grouped, sources, policy):
    limit = policy["profile_limits"][name]
    raw_catalog = policy["domain_evidence_catalog"]
    web_labels, mobile_labels = set(policy["web_label_categories"]), set(policy["mobile_sdk_labels"])
    reserved, candidates, reasons = set(), [], {}
    for rule, records in grouped.items():
        dns = any(sources[r.source].role == "dns_bypass" for r in records)
        if dns and rule.rule_type in {"HOST", "HOST-SUFFIX", "IP-CIDR", "IP6-CIDR"}:
            reserved.add(rule); reasons[rule] = "dns_passthrough"; continue
        catalog, platforms, lite = _catalog_data(rule, raw_catalog)
        labels = set(rule.value.split(".")) if rule.rule_type in {"HOST", "HOST-SUFFIX"} else set()
        random = structural_random_reasons(rule.value, policy["random_domain_policy"]) if labels else []
        consensus = len(records[0].consensus_sources) >= 2
        if random and not (catalog or consensus): reasons[rule] = "structural_random"; continue
        if name == "clash_full": eligible = bool(catalog or labels & web_labels or labels & mobile_labels or consensus)
        elif name == "qx_universal": eligible = bool(platforms & {"web", "shared"} or labels & web_labels)
        else: eligible = bool((platforms & {"mobile", "shared"} and lite) or labels & mobile_labels)
        if not eligible: reasons[rule] = "platform_excluded"; continue
        strength = 3 if catalog else 2 if consensus else 1
        candidates.append(((-strength, TYPE_ORDER[rule.rule_type], rule.value, tuple(sorted(rule.modifiers))), rule))
        reasons[rule] = "catalog" if catalog else "exact_label"
    if len(reserved) > limit["max"]: raise ValueError(f"{name} DNS reservation exceeds max")
    selected = set(reserved)
    for _, rule in sorted(candidates):
        if len(selected) >= limit["target"]:
            reasons[rule] = "target_excluded"; continue
        selected.add(rule)
    selected = _reduce(selected, reserved)
    return sorted(selected, key=lambda r: (TYPE_ORDER[r.rule_type], r.value, tuple(sorted(r.modifiers)))), reasons, {"target": limit["target"], "max": limit["max"], "reserved": len(reserved), "eligible": len(candidates)}


def build_profiles(results, policy):
    grouped = _group(results); sources = {r.source.source_id: r.source for r in results}
    profiles, reasons, summaries = {}, {}, {}
    profiles["clash_full"], reasons["clash_full"], summaries["clash_full"] = _select("clash_full", grouped, sources, policy)
    for name in ("qx_universal", "qx_compact"):
        profiles[name], reasons[name], summaries[name] = _select(name, grouped, sources, policy)
    clash = set(profiles["clash_full"])
    for name in ("qx_universal", "qx_compact"):
        clash.update(profiles[name])
    if len(clash) > policy["profile_limits"]["clash_full"]["max"]:
        raise ValueError("clash_full exceeds max after required QX containment")
    qx_reserved = set(profiles["qx_universal"]) | set(profiles["qx_compact"])
    dns_reserved = {rule for rule, records in grouped.items() if any(sources[r.source].role == "dns_bypass" for r in records)}
    profiles["clash_full"] = sorted(_reduce(clash, qx_reserved | dns_reserved), key=lambda r: (TYPE_ORDER[r.rule_type], r.value, tuple(sorted(r.modifiers))))
    clash = set(profiles["clash_full"])
    for name in ("qx_universal", "qx_compact"):
        missing = set(profiles[name]) - clash
        if missing: raise ValueError(f"{name} is not contained by clash_full: {next(iter(missing))}")
    for name in PROFILES:
        if len(profiles[name]) > policy["profile_limits"][name]["max"]: raise ValueError(f"{name} exceeds max")
    decisions = {}
    for rule, records in grouped.items():
        for record in records:
            for name in PROFILES: record.decisions[name] = "kept" if rule in profiles[name] else reasons[name].get(rule, "not_selected")
        decisions[rule] = ("kept", None) if rule in clash else ("dropped", reasons["clash_full"].get(rule))
    return profiles, decisions


def profile_summary(results, profiles, policy):
    grouped = _group(results); sources = {r.source.source_id: r.source for r in results}
    return {name: _select(name, grouped, sources, policy)[2] for name in PROFILES}
