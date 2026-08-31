from __future__ import annotations

import hashlib
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from .models import Rule, SourceResult
from .normalize import format_rule
from .parse import records_json
from .pipeline import TYPE_ORDER, profile_summary

CLASH_TYPES = {"HOST": "DOMAIN", "HOST-SUFFIX": "DOMAIN-SUFFIX", "HOST-KEYWORD": "DOMAIN-KEYWORD", "IP-CIDR": "IP-CIDR", "IP6-CIDR": "IP-CIDR6", "GEOIP": "GEOIP"}


def counts(rules: list[Rule]) -> Counter:
    return Counter(rule.rule_type for rule in rules)


def qx_text(name: str, rules: list[Rule], policy: str) -> str:
    c = counts(rules)
    lines = [f"# NAME: {name}", f"# HOST: {c['HOST']}", f"# HOST-SUFFIX: {c['HOST-SUFFIX']}", f"# HOST-KEYWORD: {c['HOST-KEYWORD']}", f"# IP-CIDR: {c['IP-CIDR'] + c['IP6-CIDR']}", f"# GEOIP: {c['GEOIP']}", f"# USER-AGENT: {c['USER-AGENT']}", f"# TOTAL: {len(rules)}"]
    lines.extend(format_rule(rule, policy) for rule in rules)
    return "\n".join(lines) + "\n"


def clash_text(name: str, rules: list[Rule]) -> str:
    unsupported = sum(rule.rule_type == "USER-AGENT" for rule in rules)
    supported = [rule for rule in rules if rule.rule_type in CLASH_TYPES]
    c = counts(supported)
    lines = [f"# NAME: {name}", f"# DOMAIN: {c['HOST']}", f"# DOMAIN-SUFFIX: {c['HOST-SUFFIX']}", f"# DOMAIN-KEYWORD: {c['HOST-KEYWORD']}", f"# IP-CIDR: {c['IP-CIDR'] + c['IP6-CIDR']}", f"# GEOIP: {c['GEOIP']}", f"# UNSUPPORTED-USER-AGENT: {unsupported}", f"# TOTAL: {len(supported)}", "payload:"]
    for rule in supported:
        fields = [CLASH_TYPES[rule.rule_type], rule.value]
        if "no-resolve" in rule.modifiers:
            fields.append("no-resolve")
        lines.append("  - " + ",".join(fields))
    return "\n".join(lines) + "\n"


def _sha(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def write_outputs(directory: Path, profiles: dict[str, list[Rule]], results: list[SourceResult], policy: dict, identity: dict, baseline: dict | None, approval: dict | None) -> dict:
    directory.mkdir(parents=True, exist_ok=True)
    policy_name = policy["qx_policy"]
    files = {
        "QX_Universal.list": qx_text("QX_Universal", profiles["qx_universal"], policy_name),
        "QX_Compact.list": qx_text("QX_Compact", profiles["qx_compact"], policy_name),
        "Clash_Unified.yaml": clash_text("Clash_Unified", profiles["clash_full"]),
    }
    record_lines = []
    for result in results:
        record_lines.extend(records_json(result.records))
    files["rule_decisions.jsonl"] = "\n".join(sorted(record_lines)) + "\n"
    safety = Counter(record.reason for result in results for record in result.records if record.reason)
    source_summary = {result.source.source_id: {"candidate_lines": result.candidate_lines, "parsed_rules": result.parsed_rules, "rejections": result.rejection_counts, "canonical_events_hash": result.canonical_events_hash, "raw_content_hash": result.raw_content_hash} for result in results}
    output_counts = {name: dict(counts(rules)) | {"TOTAL": len(rules)} for name, rules in profiles.items()}
    selection_summary = profile_summary(results, profiles, policy)
    dns_rules = {record.rule for result in results if result.source.role == "dns_bypass" for record in result.records if record.rule}
    dns_retained = {name: len(dns_rules & set(rules)) for name, rules in profiles.items()}
    report = ["# Rule Processing Report", "", "## Output rules", ""]
    for name, summary in output_counts.items():
        selection = selection_summary[name]
        report.append(f"- `{name}`: actual={summary['TOTAL']}, target={selection['target']}, max={selection['max']}; reserved DNS={selection['reserved']}; eligible={selection['eligible']}")
        report.append("  - " + ", ".join(f"{k}={v}" for k, v in sorted(summary.items()) if k != "TOTAL"))
    report.extend(["", "## BlockDNS passthrough", ""])
    report.append(f"- Normalized source rules: {len(dns_rules)}")
    for name, retained in dns_retained.items(): report.append(f"- `{name}` retained: {retained}/{len(dns_rules)}")
    report.extend(["", "## Sources", ""])
    for name, summary in source_summary.items(): report.append(f"- `{name}`: candidates={summary['candidate_lines']}, parsed={summary['parsed_rules']}, canonical={summary['canonical_events_hash']}")
    report.extend(["", "## Safety rejections", ""] + [f"- `{reason}`: {count}" for reason, count in sorted(safety.items())])
    if approval: report.extend(["", "## Manual approval", "", f"- {approval['reason']}"])
    files["Rule_Report.md"] = "\n".join(report) + "\n"
    baseline_data = {"identity": identity, "outputs": output_counts, "source_summary": source_summary, "safety_rejections": dict(safety), "root_suffixes": sorted(rule.value for rule in profiles["clash_full"] if rule.rule_type == "HOST-SUFFIX" and rule.value.count(".") == 1), "approval": approval}
    files["rule_baseline.json"] = json.dumps(baseline_data, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    for name, text in files.items(): (directory / name).write_text(text, encoding="utf-8")
    manifest = {"built_at": datetime.now(timezone.utc).isoformat(), "identity": identity, "files": {name: _sha((directory / name).read_bytes()) for name in sorted(files)}, "managed_files": sorted([*files, "manifest.json"]), "baseline_exists": baseline is not None}
    (directory / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return baseline_data
