from __future__ import annotations

import ipaddress
import re
from collections import defaultdict

from .config import policy_items
from .models import Rule, SourceConfig, SourceRecord, SourceResult
from .normalize import covered_by_suffix, normalize_domain, structural_random_reasons

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
    ip_rules = [r for r in result if r.rule_type in {"IP-CIDR", "IP6-CIDR"}]
    if ip_rules:
        ip_groups = defaultdict(list)
        for r in ip_rules:
            ip_groups[(r.rule_type, tuple(sorted(r.modifiers)))].append(r)
        for (rtype, mods), grp_rules in ip_groups.items():
            parsed_nets = [(r, ipaddress.ip_network(r.value)) for r in grp_rules]
            parsed_nets.sort(key=lambda item: (item[1].prefixlen, item[1].network_address))
            accepted_parents = []
            for r, net in parsed_nets:
                if any(net != p and net.subnet_of(p) for p in accepted_parents):
                    if r not in reserved:
                        result.discard(r)
                else:
                    accepted_parents.append(net)
    return result


def _catalog_data(rule, raw_catalog):
    matched = []
    for item in raw_catalog:
        if rule.rule_type in {"HOST", "HOST-SUFFIX"} and (rule.value == item["value"] or item["match"] == "suffix" and rule.value.endswith("." + item["value"])):
            matched.append(item)
    platforms = set().union(*(set(x["platforms"]) for x in matched)) if matched else set()
    return matched, platforms, any(x["lite_enabled"] for x in matched)


def _select(name, grouped, sources, policy, rd_sources=None):
    limit = policy["profile_limits"][name]
    raw_catalog = policy["domain_evidence_catalog"]
    web_labels, mobile_labels = set(policy["web_label_categories"]), set(policy["mobile_sdk_labels"])
    excluded_labels = set(policy["label_pattern_exclusions"])
    web_patterns = [re.compile(value) for value in policy["web_label_patterns"]]
    compact_patterns = [re.compile(value) for value in policy["compact_label_patterns"]]
    kw_root_patterns = [re.compile(value) for value in policy.get("keyword_root_patterns", [])]
    domain_exclusions = tuple(e.strip().strip(".").lower() for e in policy.get("domain_exclusions", []) if isinstance(e, str) and e.strip().strip("."))
    allowed_keywords = {item.value.lower() for item in policy_items(policy, "keyword_allowlist")} if "keyword_allowlist" in policy else set()
    reserved, candidates, reasons, tier_counts = set(), {1: [], 2: [], 3: []}, {}, defaultdict(int)
    tier3 = policy["tier3_policy"]
    for rule, records in grouped.items():
        if rule.rule_type in {"HOST", "HOST-SUFFIX"} and domain_exclusions:
            rule_val = rule.value.lower().strip(".")
            matched_exclusion = next((ex for ex in domain_exclusions if rule_val == ex or rule_val.endswith("." + ex)), None)
            if matched_exclusion:
                reasons[rule] = f"domain_exclusion:{matched_exclusion}"
                continue
        if rule.rule_type == "HOST-KEYWORD":
            rule_kw = rule.value.lower().strip(".")
            if rule_kw in allowed_keywords:
                if domain_exclusions and any(ex == rule_kw or ex.startswith(rule_kw + ".") or ("." + rule_kw + ".") in ex for ex in domain_exclusions):
                    reasons[rule] = f"domain_exclusion:{rule_kw}"
                    continue
                tier = 1
                reasons[rule] = "tier1:keyword_allowlist"
                candidates[1].append(((-990, TYPE_ORDER[rule.rule_type], len(rule.value), rule.value), rule))
                tier_counts["tier1_eligible"] += 1
                continue
            elif (len(rule_kw) >= 5 and "." not in rule_kw
                  and kw_root_patterns
                  and any(pat.fullmatch(rule_kw) for pat in kw_root_patterns)):
                if domain_exclusions and any(ex == rule_kw or ex.startswith(rule_kw + ".") or ("." + rule_kw + ".") in ex for ex in domain_exclusions):
                    reasons[rule] = f"domain_exclusion:{rule_kw}"
                    continue
                tier = 1
                reasons[rule] = "tier1:keyword_root"
                candidates[1].append(((-985, TYPE_ORDER[rule.rule_type], len(rule.value), rule.value), rule))
                tier_counts["tier1_eligible"] += 1
                continue
            else:
                reasons[rule] = "keyword_not_admissible"
                continue
        dns = any(sources[r.source].role == "dns_bypass" for r in records if r.source in sources)
        if dns and rule.rule_type in {"HOST", "HOST-SUFFIX", "IP-CIDR", "IP6-CIDR"}:
            reserved.add(rule); reasons[rule] = "tier1_dns_passthrough"; continue
        catalog, platforms, lite = _catalog_data(rule, raw_catalog)
        labels = set(rule.value.split(".")) if rule.rule_type in {"HOST", "HOST-SUFFIX"} else set()
        pattern_web = {label for label in labels if label not in excluded_labels and any(pattern.fullmatch(label) for pattern in web_patterns)}
        pattern_compact = {label for label in labels if label not in excluded_labels and any(pattern.fullmatch(label) for pattern in compact_patterns)}
        random = structural_random_reasons(rule.value, policy["random_domain_policy"]) if labels else []
        consensus_count = len(records[0].consensus_sources) if records and records[0].consensus_sources else 0
        consensus = consensus_count >= 2
        if random and not (catalog or consensus): reasons[rule] = "structural_random"; continue
        tier = None
        if catalog:
            compatible = name == "clash_full" or (name == "qx_universal" and platforms & {"web", "shared"}) or (name == "qx_compact" and platforms & {"mobile", "shared"} and lite)
            if compatible:
                tier = 1
        elif name == "clash_full" and (labels & web_labels or labels & mobile_labels or pattern_web or consensus):
            tier = 2
        elif name == "qx_universal" and (labels & web_labels or pattern_web):
            tier = 2
        elif name == "qx_compact" and (labels & mobile_labels or pattern_compact):
            tier = 2
        if tier is None and name in tier3["enabled_profiles"] and rule.rule_type in {"HOST", "HOST-SUFFIX"}:
            owner = next((platform for domain, platform in tier3["owner_platforms"].items() if rule.value == domain or rule.value.endswith("." + domain)), None)
            evidence = labels & set(tier3["label_vocabulary"])
            blocked = labels & set(tier3["excluded_labels"])
            profile_ok = name == "clash_full" or owner == "web"
            if owner and evidence and not blocked and profile_ok:
                tier = 3
        if tier is None and rule.rule_type in {"IP-CIDR", "IP6-CIDR"}:
            trusted_ad = any(
                r.source in sources and sources[r.source].role in {"advertising", "tracking"}
                for r in records
            )
            if trusted_ad:
                tier = 2
        if tier is None:
            reasons[rule] = "platform_or_evidence_excluded"
            continue

        # 消除字典序截断偏差：根据规则类型权重、共识信度、特征匹配丰富度进行科学多维排序
        is_suffix = 1 if rule.rule_type == "HOST-SUFFIX" else 0
        rd_source_count = 1
        if rd_sources and rule.rule_type in {"HOST", "HOST-SUFFIX"}:
            _, registrable, _ = normalize_domain(rule.value)
            if registrable:
                rd_source_count = len(rd_sources.get(registrable, set())) or 1

        if tier == 1:
            priority = max((item.get("priority", 800) for item in catalog), default=800)
            rank_score = (-priority, -consensus_count, -rd_source_count, -is_suffix, TYPE_ORDER.get(rule.rule_type, 99), len(rule.value), rule.value)
        elif tier == 2:
            if name == "qx_compact":
                sdk_count = len(labels & mobile_labels)
                tracker_count = len({l for l in pattern_compact if re.search(r"track", l)})
                pixel_count = len({l for l in pattern_compact if re.search(r"pixel|beacon", l)})
                analytics_count = len({l for l in pattern_compact if re.search(r"analytic", l)})
                metrics_count = len({l for l in pattern_compact if re.search(r"metric", l)})

                if sdk_count > 0:
                    evidence_grade = 50 + min(sdk_count, 5)
                elif tracker_count > 0:
                    evidence_grade = 40 + min(tracker_count, 5)
                elif pixel_count > 0:
                    evidence_grade = 30 + min(pixel_count, 5)
                elif analytics_count > 0:
                    evidence_grade = 20 + min(analytics_count, 5)
                elif metrics_count > 0:
                    parts = rule.value.split(".")
                    is_special_metric = any("-" in l or "_" in l or l == "metric" for l in pattern_compact) or len(parts) != 3
                    evidence_grade = 15 if is_special_metric else 10
                else:
                    evidence_grade = 5
            else:
                evidence_grade = len(labels & (web_labels | mobile_labels)) + len(pattern_web)
            rank_score = (-consensus_count, -evidence_grade, -rd_source_count, -is_suffix, TYPE_ORDER.get(rule.rule_type, 99), len(rule.value), rule.value)
        else:
            rank_score = (-consensus_count, -rd_source_count, -is_suffix, TYPE_ORDER.get(rule.rule_type, 99), len(rule.value), rule.value)

        candidates[tier].append((rank_score, rule))
        reasons[rule] = f"tier{tier}:catalog" if tier == 1 else f"tier{tier}:label_or_evidence"
        tier_counts[f"tier{tier}_eligible"] += 1
    if len(reserved) > limit["max"]: raise ValueError(f"{name} DNS reservation exceeds max")
    selected = set(reserved)
    rule_tier_map: dict[Rule, int] = {}
    current_suffixes = {r.value for r in selected if r.rule_type == "HOST-SUFFIX"}
    target_cap = limit["target"]
    hard_max = limit["max"]

    # 优化容量调度：质量分梯度平滑录取与弹性缓冲区，避免死板硬截断与分档撕裂
    active_bracket = None
    for tier in (1, 2, 3):
        for rank_score, rule in sorted(candidates[tier]):
            if rule.rule_type in {"HOST", "HOST-SUFFIX"} and rule not in reserved:
                if covered_by_suffix(rule.value, current_suffixes - ({rule.value} if rule.rule_type == "HOST-SUFFIX" else set())):
                    reasons[rule] = "covered_by_active_suffix"
                    continue
            bracket_key = (tier, rank_score[0], rank_score[1], rank_score[2])
            is_core = (tier == 1) or (rule in grouped and len(grouped[rule][0].consensus_sources) >= 2)
            current_count = len(selected)
            if is_core:
                if current_count >= hard_max:
                    reasons[rule] = f"max_exceeded_tier{tier}"
                    continue
                active_bracket = bracket_key
            else:
                if current_count >= target_cap:
                    buffer = max(1, int(target_cap * 0.15))
                    soft_cap = min(hard_max, target_cap + buffer)
                    if bracket_key != active_bracket or current_count >= soft_cap:
                        reasons[rule] = f"target_reached_tier{tier}"
                        continue
                active_bracket = bracket_key
            selected.add(rule)
            rule_tier_map[rule] = tier
            if rule.rule_type == "HOST-SUFFIX":
                current_suffixes.add(rule.value)
                # 动态折叠已被新后缀覆盖的已选非保留子域规则，立即释放预算名额并校准计数
                covered_selected = [
                    existing for existing in selected
                    if existing is not rule
                    and existing not in reserved
                    and existing.rule_type in {"HOST", "HOST-SUFFIX"}
                    and (existing.value == rule.value or existing.value.endswith("." + rule.value))
                ]
                for existing in covered_selected:
                    selected.discard(existing)
                    ex_tier = rule_tier_map.pop(existing, None)
                    if ex_tier is not None:
                        tier_counts[f"tier{ex_tier}_selected"] = max(0, tier_counts[f"tier{ex_tier}_selected"] - 1)
                    if existing.rule_type == "HOST-SUFFIX":
                        current_suffixes.discard(existing.value)
                    reasons[existing] = "covered_by_active_suffix"
            tier_counts[f"tier{tier}_selected"] += 1
    selected = _reduce(selected, reserved)
    summary = {"target": limit["target"], "max": limit["max"], "reserved": len(reserved), "eligible": sum(len(items) for items in candidates.values())}
    return sorted(selected, key=lambda r: (TYPE_ORDER[r.rule_type], r.value, tuple(sorted(r.modifiers)))), reasons, summary | dict(tier_counts)


def _sources_map(results):
    sources = {r.source.source_id: r.source for r in results}
    sources["domain_catalog_seed"] = SourceConfig("domain_catalog_seed", "", "catalog", "trusted", False, (), 0, 0)
    return sources


def _group_and_seed(results, policy):
    grouped = _group(results)
    raw_catalog = policy.get("domain_evidence_catalog", [])
    for item in raw_catalog:
        cat_val = item["value"].lower()
        is_suffix = item.get("match") == "suffix"
        has_match = any(
            r.rule_type in {"HOST", "HOST-SUFFIX"} and (r.value == cat_val or (is_suffix and r.value.endswith("." + cat_val)))
            for r in grouped
        )
        if not has_match:
            cat_rule = Rule("HOST-SUFFIX" if is_suffix else "HOST", cat_val)
            seed_record = SourceRecord(
                source="domain_catalog_seed",
                line_number=0,
                original_rule=f"CATALOG,{cat_val}",
                rule=cat_rule,
                status="accepted",
                reason="catalog_seed_injection",
                consensus_sources=["domain_catalog_seed"]
            )
            grouped[cat_rule].append(seed_record)
    rd_sources = defaultdict(set)
    for rule, records in grouped.items():
        if rule.rule_type in {"HOST", "HOST-SUFFIX"}:
            _, registrable, _ = normalize_domain(rule.value)
            if registrable:
                for rec in records:
                    if rec.source != "domain_catalog_seed":
                        rd_sources[registrable].add(rec.source)
    return grouped, dict(rd_sources)


def build_profiles(results, policy):
    grouped, rd_sources = _group_and_seed(results, policy)
    sources = _sources_map(results)
    profiles, reasons, summaries = {}, {}, {}
    profiles["clash_full"], reasons["clash_full"], summaries["clash_full"] = _select("clash_full", grouped, sources, policy, rd_sources)
    for name in ("qx_universal", "qx_compact"):
        profiles[name], reasons[name], summaries[name] = _select(name, grouped, sources, policy, rd_sources)
    clash = set(profiles["clash_full"])
    for name in ("qx_universal", "qx_compact"):
        clash.update(profiles[name])
    if len(clash) > policy["profile_limits"]["clash_full"]["max"]:
        raise ValueError("clash_full exceeds max after required QX containment")
    qx_reserved = set(profiles["qx_universal"]) | set(profiles["qx_compact"])
    dns_reserved = {rule for rule, records in grouped.items() if any(sources.get(r.source, None) and sources[r.source].role == "dns_bypass" for r in records)}
    profiles["clash_full"] = sorted(_reduce(clash, qx_reserved | dns_reserved), key=lambda r: (TYPE_ORDER[r.rule_type], r.value, tuple(sorted(r.modifiers))))
    clash = set(profiles["clash_full"])
    for name in ("qx_universal", "qx_compact"):
        missing = set(profiles[name]) - clash
        if missing: raise ValueError(f"{name} is not contained by clash_full: {next(iter(missing))}")
    for name in PROFILES:
        if len(profiles[name]) > policy["profile_limits"][name]["max"]: raise ValueError(f"{name} exceeds max")
    decisions = {}
    profile_sets = {name: set(profiles[name]) for name in PROFILES}
    clash_set = profile_sets["clash_full"]
    for rule, records in grouped.items():
        is_kept_clash = rule in clash_set
        for record in records:
            for name in PROFILES:
                record.decisions[name] = "kept" if rule in profile_sets[name] else reasons[name].get(rule, "not_selected")
        decisions[rule] = ("kept", None) if is_kept_clash else ("dropped", reasons["clash_full"].get(rule))
    return profiles, decisions


def profile_summary(results, profiles, policy):
    grouped, rd_sources = _group_and_seed(results, policy)
    sources = _sources_map(results)
    return {name: _select(name, grouped, sources, policy, rd_sources)[2] for name in PROFILES}
