from __future__ import annotations

import ipaddress
from collections import defaultdict

from .config import policy_items
from .models import Rule, SourceRecord, SourceResult
from .normalize import covered_by_suffix

TYPE_ORDER = {"HOST": 1, "HOST-SUFFIX": 2, "HOST-KEYWORD": 3, "IP-CIDR": 4, "IP6-CIDR": 5, "GEOIP": 6, "USER-AGENT": 7}


def _matches(value: str, item) -> bool:
    return value == item.value if item.match == "exact" else value == item.value or value.endswith("." + item.value)


def _allowed_by_items(rule: Rule, items) -> bool:
    return any(_matches(rule.value, item) for item in items)


def _dedupe_records(results: list[SourceResult]) -> dict[Rule, list[SourceRecord]]:
    grouped: dict[Rule, list[SourceRecord]] = defaultdict(list)
    for result in results:
        for record in result.records:
            if record.rule:
                grouped[record.rule].append(record)
    allowed = {result.source.source_id for result in results if result.source.participates_in_consensus}
    for rule, records in grouped.items():
        consensus = sorted({record.source for record in records} & allowed)
        for record in records:
            record.consensus_sources = consensus
    return grouped


def _dedupe_cidrs(rules: set[Rule], decisions: dict[Rule, tuple[str, str | None]]) -> set[Rule]:
    grouped: dict[tuple[str, frozenset[str]], list[tuple[ipaddress._BaseNetwork, Rule]]] = defaultdict(list)
    other: set[Rule] = set()
    for rule in rules:
        if rule.rule_type not in {"IP-CIDR", "IP6-CIDR"}:
            other.add(rule)
            continue
        grouped[(rule.rule_type, rule.modifiers)].append((ipaddress.ip_network(rule.value), rule))
    for _, entries in grouped.items():
        # Same address scope: keep no-resolve when both variants exist; modifiers are grouped here.
        entries.sort(key=lambda pair: (pair[0].prefixlen, int(pair[0].network_address)))
        kept: list[tuple[ipaddress._BaseNetwork, Rule]] = []
        for network, rule in entries:
            parent = next((parent_rule for parent_net, parent_rule in kept if network.subnet_of(parent_net)), None)
            if parent:
                decisions[rule] = ("dropped", f"covered_by_cidr:{parent.value}")
            else:
                kept.append((network, rule))
                other.add(rule)
    # Resolve exactly equal CIDRs with different modifiers in favor of no-resolve.
    identities: dict[tuple[str, str], Rule] = {}
    for rule in sorted(other, key=lambda r: (r.rule_type, r.value, tuple(sorted(r.modifiers)))):
        if rule.rule_type not in {"IP-CIDR", "IP6-CIDR"}:
            continue
        key = (rule.rule_type, rule.value)
        previous = identities.get(key)
        if previous and "no-resolve" in rule.modifiers and "no-resolve" not in previous.modifiers:
            other.remove(previous)
            decisions[previous] = ("dropped", "duplicate_prefer_no_resolve")
            identities[key] = rule
        elif previous and "no-resolve" in previous.modifiers and "no-resolve" not in rule.modifiers:
            other.remove(rule)
            decisions[rule] = ("dropped", "duplicate_prefer_no_resolve")
        else:
            identities[key] = rule
    return other


def _suffix_reduce(rules: set[Rule], decisions: dict[Rule, tuple[str, str | None]]) -> set[Rule]:
    suffixes = {rule.value for rule in rules if rule.rule_type == "HOST-SUFFIX"}
    keep = set(rules)
    for rule in sorted(rules, key=lambda r: (TYPE_ORDER.get(r.rule_type, 99), r.value)):
        if rule.rule_type not in {"HOST", "HOST-SUFFIX"}:
            continue
        candidates = suffixes - ({rule.value} if rule.rule_type == "HOST-SUFFIX" else set())
        cover = covered_by_suffix(rule.value, candidates)
        if cover:
            keep.remove(rule)
            decisions[rule] = ("dropped", f"covered_by_suffix:{cover}")
    return keep


def build_profiles(results: list[SourceResult], policy: dict) -> tuple[dict[str, list[Rule]], dict[Rule, tuple[str, str | None]]]:
    grouped = _dedupe_records(results)
    all_rules = set(grouped)
    decisions: dict[Rule, tuple[str, str | None]] = {rule: ("kept", None) for rule in all_rules}
    stable = _suffix_reduce(all_rules, decisions)
    stable = _dedupe_cidrs(stable, decisions)

    keyword_items = policy_items(policy, "keyword_allowlist")
    lite_items = policy_items(policy, "lite_allowlist")
    mobile_geoip = {str(value).upper() for value in policy.get("mobile_geoip_allowlist", [])}
    sources = {result.source.source_id: result.source for result in results}

    mobile: set[Rule] = set()
    lite: set[Rule] = set()
    for rule in stable:
        records = grouped[rule]
        record_sources = {record.source for record in records}
        is_dns = any(sources[source].role == "dns_bypass" for source in record_sources)
        consensus = len({source for source in record_sources if sources[source].participates_in_consensus}) >= 2
        keyword_ok = rule.rule_type == "HOST-KEYWORD" and _allowed_by_items(rule, keyword_items)
        geo_ok = rule.rule_type == "GEOIP" and rule.value in mobile_geoip
        if rule.rule_type != "HOST-KEYWORD" and (rule.rule_type != "GEOIP" or geo_ok):
            mobile.add(rule)
        elif keyword_ok:
            mobile.add(rule)

        dns_allowed = is_dns and rule.rule_type in {"HOST", "HOST-SUFFIX", "IP-CIDR", "IP6-CIDR"}
        allowlisted = _allowed_by_items(rule, lite_items) if rule.rule_type in {"HOST", "HOST-SUFFIX"} else keyword_ok
        if rule.rule_type == "GEOIP":
            accepted = geo_ok
        elif rule.rule_type == "USER-AGENT":
            accepted = keyword_ok
        else:
            accepted = dns_allowed or consensus or allowlisted
        if accepted:
            lite.add(rule)

    for rule, records in grouped.items():
        for record in records:
            if rule not in stable:
                record.decisions["stable"] = decisions.get(rule, ("dropped", "deduplicated"))[1] or "dropped"
            else:
                record.decisions["stable"] = "kept"
            record.decisions["mobile_stable"] = "kept" if rule in mobile else "mobile_profile_filter"
            record.decisions["lite"] = "kept" if rule in lite else "lite_low_confidence"
            if rule in decisions and decisions[rule][1] and rule not in stable:
                record.covered_by = decisions[rule][1]
    return {"mac": sorted(stable, key=lambda r: (TYPE_ORDER[r.rule_type], r.value, tuple(sorted(r.modifiers)))), "mobile": sorted(mobile, key=lambda r: (TYPE_ORDER[r.rule_type], r.value, tuple(sorted(r.modifiers)))), "lite": sorted(lite, key=lambda r: (TYPE_ORDER[r.rule_type], r.value, tuple(sorted(r.modifiers))))}, decisions
