from __future__ import annotations

from dataclasses import dataclass, field
from typing import FrozenSet


@dataclass(frozen=True, order=True)
class Rule:
    rule_type: str
    value: str
    modifiers: FrozenSet[str] = frozenset()

    @property
    def key(self) -> tuple[str, str, tuple[str, ...]]:
        return self.rule_type, self.value, tuple(sorted(self.modifiers))


@dataclass
class SourceRecord:
    source: str
    line_number: int
    original_rule: str
    rule: Rule | None
    status: str
    reason: str | None = None
    removed_modifiers: list[str] = field(default_factory=list)
    duplicate_count: int = 1
    psl_status: str | None = None
    registrable_domain: str | None = None
    consensus_sources: list[str] = field(default_factory=list)
    decisions: dict[str, str] = field(default_factory=dict)
    covered_by: str | None = None


@dataclass(frozen=True)
class SourceConfig:
    source_id: str
    url: str
    role: str
    tier: str
    participates_in_consensus: bool
    allowed_hosts: tuple[str, ...]
    max_bytes: int
    max_rules: int


@dataclass
class SourceResult:
    source: SourceConfig
    raw_content_hash: str
    canonical_events_hash: str
    records: list[SourceRecord]
    candidate_lines: int
    parsed_rules: int
    rejection_counts: dict[str, int]
