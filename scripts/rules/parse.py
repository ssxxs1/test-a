from __future__ import annotations

import hashlib
import json
from collections import Counter

from .models import Rule, SourceRecord, SourceResult
from .normalize import is_ip_literal, normalize_domain, normalize_ip, normalize_keyword

TYPE_MAP = {
    "DOMAIN": "HOST", "HOST": "HOST",
    "DOMAIN-SUFFIX": "HOST-SUFFIX", "HOST-SUFFIX": "HOST-SUFFIX",
    "DOMAIN-KEYWORD": "HOST-KEYWORD", "HOST-KEYWORD": "HOST-KEYWORD",
    "IP-CIDR": "IP-CIDR", "IP-CIDR6": "IP6-CIDR", "IP6-CIDR": "IP6-CIDR",
    "GEOIP": "GEOIP", "USER-AGENT": "USER-AGENT",
}
COMMENT_PREFIXES = ("#", "//", "!", ";")


def _event(record: SourceRecord) -> str:
    if record.rule:
        return json.dumps({"kind": "rule", "type": record.rule.rule_type, "value": record.rule.value, "modifiers": sorted(record.rule.modifiers)}, sort_keys=True)
    return "|".join(("reject", record.status, record.reason or "", record.original_rule))


def parse_source(source, content: bytes, policy: dict) -> SourceResult:
    text = content.decode("utf-8", errors="replace")
    raw_hash = hashlib.sha256(content).hexdigest()
    candidates = 0
    records: list[SourceRecord] = []
    reject_counts: Counter[str] = Counter()
    denylist = set(policy.get("keyword_denylist", []))
    for line_number, original in enumerate(text.splitlines(), 1):
        line = original.strip()
        if not line or line.startswith(COMMENT_PREFIXES):
            continue
        candidates += 1
        parts = [part.strip() for part in line.split(",")]
        if len(parts) < 2:
            reason = "invalid_format"
            records.append(SourceRecord(source.source_id, line_number, original, None, "rejected", reason))
            reject_counts[reason] += 1
            continue
        raw_type = parts[0].upper()
        canonical_type = TYPE_MAP.get(raw_type)
        if not canonical_type:
            reason = "unsupported_type"
            records.append(SourceRecord(source.source_id, line_number, original, None, "rejected", reason))
            reject_counts[reason] += 1
            continue
        value = parts[1]
        input_modifiers = {part.lower() for part in parts[3:] if part}
        if len(parts) > 2 and parts[2].lower() == "no-resolve":
            input_modifiers.add("no-resolve")
        allowed = {"no-resolve"} if canonical_type in {"IP-CIDR", "IP6-CIDR"} else set()
        modifiers = frozenset(input_modifiers & allowed)
        removed = sorted(input_modifiers - allowed)
        normalized_value: str | None
        reason: str | None = None
        psl_status: str | None = None
        registrable: str | None = None
        if canonical_type in {"HOST", "HOST-SUFFIX"}:
            normalized_value, registrable, reason = normalize_domain(value)
            if normalized_value and is_ip_literal(normalized_value) and canonical_type == "HOST-SUFFIX":
                normalized_value, reason = None, "ip_suffix_not_supported"
            psl_status = "ip_literal" if normalized_value and is_ip_literal(normalized_value) else ("recognized" if normalized_value else reason)
        elif canonical_type == "HOST-KEYWORD":
            normalized_value, reason = normalize_keyword(value, denylist)
        elif canonical_type == "IP-CIDR":
            normalized_value, reason = normalize_ip(value, 4)
        elif canonical_type == "IP6-CIDR":
            normalized_value, reason = normalize_ip(value, 6)
        elif canonical_type == "GEOIP":
            normalized_value = value.upper()
            if not normalized_value.isalpha() or not 2 <= len(normalized_value) <= 3:
                normalized_value, reason = None, "invalid_geoip"
        else:
            normalized_value = value.strip()
            if not normalized_value:
                normalized_value, reason = None, "invalid_user_agent"
        if not normalized_value:
            records.append(SourceRecord(source.source_id, line_number, original, None, "rejected", reason or "invalid_rule", removed, psl_status=psl_status, registrable_domain=registrable))
            reject_counts[reason or "invalid_rule"] += 1
            continue
        records.append(SourceRecord(source.source_id, line_number, original, Rule(canonical_type, normalized_value, modifiers), "accepted", removed_modifiers=removed, psl_status=psl_status, registrable_domain=registrable))
    events = sorted(_event(record) for record in records)
    canonical_hash = hashlib.sha256("\n".join(events).encode()).hexdigest()
    return SourceResult(source, raw_hash, canonical_hash, records, candidates, sum(1 for r in records if r.rule), dict(reject_counts))


def consolidate_source_records(records: list[SourceRecord]) -> list[SourceRecord]:
    grouped: dict[tuple, SourceRecord] = {}
    for record in records:
        key = record.rule.key if record.rule else (record.status, record.reason, record.original_rule)
        if key in grouped:
            grouped[key].duplicate_count += 1
        else:
            grouped[key] = record
    return list(grouped.values())


def records_json(records: list[SourceRecord]) -> list[str]:
    rows = []
    for r in records:
        rule = r.rule
        rows.append(json.dumps({
            "source": r.source, "line_number": r.line_number, "original_rule": r.original_rule,
            "normalized_rule": None if not rule else {"type": rule.rule_type, "value": rule.value, "modifiers": sorted(rule.modifiers)},
            "status": r.status, "reason": r.reason, "removed_modifiers": r.removed_modifiers,
            "source_duplicate_count": r.duplicate_count, "psl_status": r.psl_status,
            "registrable_domain": r.registrable_domain, "consensus_sources": r.consensus_sources,
            "decisions": r.decisions, "covered_by": r.covered_by,
        }, ensure_ascii=False, sort_keys=True))
    return rows
