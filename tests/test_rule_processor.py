import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from rules.models import Rule, SourceConfig, SourceRecord, SourceResult
from rules.normalize import normalize_domain
from rules.pipeline import build_profiles


POLICY = {
    "profile_limits": {"clash_full": {"target": 12, "max": 20}, "qx_universal": {"target": 10, "max": 20}, "qx_compact": {"target": 2, "max": 5}},
    "random_domain_policy": {"hex_label_min_length": 12, "numeric_label_min_length": 12, "mixed_label_min_length": 18, "mixed_label_min_digit_ratio": 0.5},
    "web_label_categories": ["ads", "tracker", "analytics", "pixel"],
    "web_label_patterns": [r"^ad(?:s)?(?:[0-9]+|[-_]?(?:server|service))?$", r"^tracker(?:[-_]?sdk)?$"],
    "compact_label_patterns": [r"^tracker(?:[-_]?sdk)?$"],
    "label_pattern_exclusions": ["adobe", "adidas"],
    "mobile_sdk_labels": ["pangle", "appsflyer"],
    "tier3_policy": {"enabled_profiles": ["clash_full", "qx_universal"], "label_vocabulary": ["ad", "ads"], "owner_platforms": {"example.com": "web"}, "excluded_labels": ["api"]},
    "domain_evidence_catalog": [
        {"id": "web", "value": "webads.example", "match": "suffix", "platforms": ["web"], "lite_enabled": False, "provider": "test", "product": "web", "priority": 1},
        {"id": "mobile", "value": "pangle.io", "match": "suffix", "platforms": ["mobile"], "lite_enabled": True, "provider": "test", "product": "mobile", "priority": 1},
        {"id": "shared", "value": "shared.example", "match": "suffix", "platforms": ["shared"], "lite_enabled": True, "provider": "test", "product": "shared", "priority": 1},
    ],
}


def result(source_id, role, rules, consensus=False):
    source = SourceConfig(source_id, "https://example.com", role, "trusted", consensus, ("example.com",), 1000, 1000)
    records = [SourceRecord(source_id, index + 1, str(rule), rule, "accepted") for index, rule in enumerate(rules)]
    return SourceResult(source, "raw", "canonical", records, len(rules), len(rules), {})


class ProductProfileTests(unittest.TestCase):
    def test_private_suffix_root_rejected(self):
        self.assertEqual(normalize_domain("blogspot.com")[2], "public_suffix_root")
        self.assertEqual(normalize_domain("ads.foo.blogspot.com")[1], "foo.blogspot.com")

    def test_host_never_promoted(self):
        host = Rule("HOST", "metrics.adobe.com")
        profiles, _ = build_profiles([result("privacy", "tracking", [host])], POLICY)
        self.assertNotIn(Rule("HOST-SUFFIX", "adobe.com"), profiles["clash_full"])

    def test_platform_routing_and_non_subset(self):
        web = Rule("HOST", "api.webads.example")
        mobile = Rule("HOST", "api.pangle.io")
        shared = Rule("HOST", "api.shared.example")
        profiles, _ = build_profiles([result("privacy", "tracking", [web, mobile, shared])], POLICY)
        self.assertIn(web, profiles["clash_full"]); self.assertIn(web, profiles["qx_universal"]); self.assertNotIn(web, profiles["qx_compact"])
        self.assertIn(mobile, profiles["clash_full"]); self.assertNotIn(mobile, profiles["qx_universal"]); self.assertIn(mobile, profiles["qx_compact"])
        self.assertIn(shared, profiles["qx_universal"]); self.assertIn(shared, profiles["qx_compact"])

    def test_exact_label_not_substring(self):
        good = Rule("HOST", "adserver.example.com")
        bad = Rule("HOST", "adidas.example.com")
        profiles, _ = build_profiles([result("privacy", "tracking", [good, bad])], POLICY)
        self.assertIn(good, profiles["qx_universal"])
        self.assertNotIn(bad, profiles["clash_full"])

    def test_random_domain_excluded(self):
        random_host = Rule("HOST", "04426f8b7ce9b069431.com")
        profiles, _ = build_profiles([result("privacy", "tracking", [random_host])], POLICY)
        self.assertFalse(any(random_host in rules for rules in profiles.values()))

    def test_dns_passthrough_all_products(self):
        host = Rule("HOST", "httpdns.push.oppomobile.com")
        suffix = Rule("HOST-SUFFIX", "httpdns.push.oppomobile.com")
        profiles, _ = build_profiles([result("BlockDNS", "dns_bypass", [host, suffix])], POLICY)
        for rules in profiles.values(): self.assertIn(host, rules); self.assertIn(suffix, rules)

    def test_elimination_of_lexicographical_bias(self):
        # r_z starts with z but has consensus (2 sources); r_a starts with a but only 1 source
        r_a = Rule("HOST-SUFFIX", "adserver-a.example.com")
        r_z = Rule("HOST-SUFFIX", "adserver-z.example.com")
        # Set target=1, max=5 for clash profile to force truncation
        custom_policy = dict(POLICY)
        custom_policy["profile_limits"] = {"clash_full": {"target": 1, "max": 5}, "qx_universal": {"target": 10, "max": 20}, "qx_compact": {"target": 2, "max": 5}}
        res1 = result("privacy", "tracking", [r_a, r_z], consensus=True)
        res2 = result("adlite", "advertising", [r_z], consensus=True)
        profiles, _ = build_profiles([res1, res2], custom_policy)
        # r_z has 2 sources consensus, so it MUST be selected over r_a despite starting with z!
        self.assertIn(r_z, profiles["clash_full"])
        self.assertNotIn(r_a, profiles["clash_full"])

    def test_keyword_allowlist_admissibility(self):
        kw_allowed = Rule("HOST-KEYWORD", "pangle")
        kw_denied = Rule("HOST-KEYWORD", "randomjunkword")
        custom_policy = dict(POLICY)
        custom_policy["keyword_allowlist"] = [{"id": "kw-pangle", "value": "pangle", "category": "sdk", "note": "x", "evidence": "x"}]
        profiles, decisions = build_profiles([result("privacy", "tracking", [kw_allowed, kw_denied])], custom_policy)
        self.assertIn(kw_allowed, profiles["clash_full"])
        self.assertNotIn(kw_denied, profiles["clash_full"])

    def test_catalog_seed_injection(self):
        # Catalog has pangle.io (lite_enabled=True, platforms=["mobile"]).
        # If upstream does not provide pangle.io at all, it should be seeded as a seed rule!
        profiles, _ = build_profiles([result("privacy", "tracking", [])], POLICY)
        self.assertIn(Rule("HOST-SUFFIX", "pangle.io"), profiles["qx_compact"])
        self.assertIn(Rule("HOST-SUFFIX", "pangle.io"), profiles["clash_full"])


if __name__ == "__main__": unittest.main()
