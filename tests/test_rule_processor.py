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
    "mobile_sdk_labels": ["pangle", "appsflyer"],
    "domain_evidence_catalog": [
        {"id": "web", "value": "webads.example", "match": "suffix", "platforms": ["web"], "lite_enabled": False},
        {"id": "mobile", "value": "pangle.io", "match": "suffix", "platforms": ["mobile"], "lite_enabled": True},
        {"id": "shared", "value": "shared.example", "match": "suffix", "platforms": ["shared"], "lite_enabled": True},
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
        good = Rule("HOST", "ads.example.com")
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


if __name__ == "__main__": unittest.main()
