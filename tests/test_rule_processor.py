import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

from rules.models import Rule, SourceConfig, SourceRecord, SourceResult
from rules.normalize import normalize_domain
from rules.pipeline import build_profiles


def source_result(source_id, role, consensus, rules):
    source = SourceConfig(source_id, "https://example.com/list", role, "trusted", consensus, ("example.com",), 1000, 1000)
    records = [SourceRecord(source_id, index + 1, f"{rule.rule_type},{rule.value}", rule, "accepted") for index, rule in enumerate(rules)]
    return SourceResult(source, "raw", "canonical", records, len(rules), len(rules), {})


POLICY = {
    "keyword_denylist": ["api", "log", "stat", "track", "report", "metrics", "analytics"],
    "keyword_allowlist": [{"id": "kw", "value": "appsflyer", "category": "sdk", "note": "x", "evidence": "x"}],
    "domain_evidence_catalog": [{"id": "sdk", "value": "appsflyer.com", "match": "suffix", "category": "sdk", "note": "x", "evidence": "x", "profiles": ["mac", "mobile", "lite"]}],
    "profile_limits": {"mac": 20000, "mobile": 10000, "lite": 2000},
    "random_domain_policy": {"hex_label_min_length": 12, "numeric_label_min_length": 12, "mixed_label_min_length": 18, "mixed_label_min_digit_ratio": 0.5},
    "admission_label_tokens": ["ads", "pixel", "tracker", "analytics"],
    "mobile_geoip_allowlist": [],
}


class DomainSafetyTests(unittest.TestCase):
    def test_private_suffix_root_is_rejected_but_tenant_is_valid(self):
        self.assertEqual(normalize_domain("blogspot.com")[2], "public_suffix_root")
        domain, registrable, reason = normalize_domain("ads.foo.blogspot.com")
        self.assertEqual(domain, "ads.foo.blogspot.com")
        self.assertEqual(registrable, "foo.blogspot.com")
        self.assertIsNone(reason)

    def test_host_is_never_promoted_to_suffix(self):
        host = Rule("HOST", "metrics.adobe.com")
        profiles, _ = build_profiles([source_result("privacy", "tracking", True, [host])], POLICY)
        self.assertNotIn(Rule("HOST-SUFFIX", "adobe.com"), profiles["mac"])
        self.assertNotIn(host, profiles["mac"])

    def test_only_final_suffix_covers_child(self):
        parent = Rule("HOST-SUFFIX", "ads.example.com")
        child = Rule("HOST", "pixel.ads.example.com")
        profiles, _ = build_profiles([source_result("privacy", "tracking", True, [parent, child])], POLICY)
        self.assertIn(parent, profiles["mac"])
        self.assertNotIn(child, profiles["mac"])

    def test_lite_allows_exact_label_categories(self):
        single = Rule("HOST", "ads.example.net")
        shared = Rule("HOST", "ads.example.org")
        sdk = Rule("HOST", "api.appsflyer.com")
        profiles, _ = build_profiles([
            source_result("privacy", "tracking", True, [single, shared, sdk]),
            source_result("adlite", "advertising", True, [shared]),
        ], POLICY)
        self.assertIn(single, profiles["lite"])
        self.assertIn(shared, profiles["lite"])
        self.assertIn(sdk, profiles["lite"])

    def test_mobile_keeps_only_allowlisted_keywords(self):
        generic = Rule("HOST-KEYWORD", "somevendor")
        allowed = Rule("HOST-KEYWORD", "appsflyer")
        profiles, _ = build_profiles([source_result("privacy", "tracking", True, [generic, allowed])], POLICY)
        self.assertNotIn(generic, profiles["mac"])
        self.assertNotIn(generic, profiles["mobile"])
        self.assertIn(allowed, profiles["mobile"])
        self.assertIn(allowed, profiles["lite"])

    def test_cidr_prefer_no_resolve(self):
        bare = Rule("IP-CIDR", "198.51.100.0/24")
        flagged = Rule("IP-CIDR", "198.51.100.0/24", frozenset({"no-resolve"}))
        profiles, _ = build_profiles([
            source_result("privacy", "tracking", True, [bare, flagged]),
            source_result("adlite", "advertising", True, [flagged]),
        ], POLICY)
        self.assertNotIn(bare, profiles["mac"])
        self.assertIn(flagged, profiles["mac"])
    def test_structurally_random_domain_is_excluded(self):
        random_host = Rule("HOST", "04426f8b7ce9b069431.com")
        profiles, _ = build_profiles([source_result("privacy", "tracking", True, [random_host])], POLICY)
        self.assertNotIn(random_host, profiles["mac"])
        self.assertNotIn(random_host, profiles["lite"])

    def test_dns_passthrough_survives_suffix_reduction(self):
        host = Rule("HOST", "httpdns.push.oppomobile.com")
        suffix = Rule("HOST-SUFFIX", "httpdns.push.oppomobile.com")
        profiles, _ = build_profiles([source_result("BlockDNS", "dns_bypass", False, [host, suffix])], POLICY)
        for profile in profiles.values():
            self.assertIn(host, profile)
            self.assertIn(suffix, profile)


if __name__ == "__main__":
    unittest.main()
