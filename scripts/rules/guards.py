from __future__ import annotations

from typing import Any


class GuardError(RuntimeError):
    pass


def verify_baseline(current: dict[str, Any], baseline: dict[str, Any] | None, policy: dict[str, Any], allow_anomaly: bool, initialize: bool) -> list[str]:
    if initialize or baseline is None:
        return []
    prior_identity = baseline.get("identity", {})
    current_identity = current.get("identity", {})
    version_pairs = (("policy_version", "policy_version"), ("sources_version", "sources_version"), ("processor_version", "processor_version"))
    for key, _ in version_pairs:
        if current_identity.get(key) != prior_identity.get(key):
            raise GuardError(f"{key} changed; create and review a preview before initializing a new baseline")
    for key in ("policy_hash", "sources_hash", "processor_hash", "dependency_identity"):
        if current_identity.get(key) != prior_identity.get(key):
            raise GuardError(f"{key} changed without a version upgrade")
    warnings: list[str] = []
    guards = policy["release_guards"]
    pct = guards["output_total_change_pct"]
    for profile, summary in current["outputs"].items():
        old = baseline.get("outputs", {}).get(profile, {}).get("TOTAL", 0)
        new = summary["TOTAL"]
        if old and abs(new - old) / old * 100 > pct:
            warnings.append(f"{profile} total changed from {old} to {new}")
    old_roots = set(baseline.get("root_suffixes", []))
    new_roots = set(current.get("root_suffixes", []))
    if guards.get("block_new_root_suffix") and new_roots - old_roots:
        warnings.append("new eTLD+1 HOST-SUFFIX rules: " + ", ".join(sorted(new_roots - old_roots)[:20]))
    for source, summary in current["source_summary"].items():
        candidates = summary["candidate_lines"]
        rejected = sum(summary["rejections"].values())
        if candidates and rejected / candidates * 100 > guards["max_rejection_rate_pct"]:
            warnings.append(f"{source} rejection rate exceeds guard")
    if warnings and not allow_anomaly:
        raise GuardError("Publish guards blocked output: " + "; ".join(warnings))
    return warnings
