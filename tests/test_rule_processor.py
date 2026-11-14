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

    def test_domain_exclusions_bypass(self):
        # Excluded domains should be dropped even if matched by mobile_sdk_labels or tracking
        r_getui = Rule("HOST-SUFFIX", "getui.com")
        r_sub_getui = Rule("HOST", "sdk.getui.net")
        r_alipay_collect = Rule("HOST-SUFFIX", "collect.alipay.com")
        r_ad = Rule("HOST-SUFFIX", "adserver.example.com")

        custom_policy = dict(POLICY)
        custom_policy["domain_exclusions"] = ["getui.com", "getui.net", "collect.alipay.com"]

        res = result("privacy", "tracking", [r_getui, r_sub_getui, r_alipay_collect, r_ad])
        profiles, decisions = build_profiles([res], custom_policy)

        for name, profile in profiles.items():
            self.assertNotIn(r_getui, profile)
            self.assertNotIn(r_sub_getui, profile)
            self.assertNotIn(r_alipay_collect, profile)

        # Verify decision reasons
        self.assertEqual(decisions[r_getui], ("dropped", "domain_exclusion:getui.com"))
        self.assertEqual(decisions[r_sub_getui], ("dropped", "domain_exclusion:getui.net"))
        self.assertEqual(decisions[r_alipay_collect], ("dropped", "domain_exclusion:collect.alipay.com"))

    def test_domain_exclusions_hardened_edge_cases(self):
        # Exclusions with leading/trailing dots, precedence over DNS bypass, and keyword blocking
        r_dns_bank = Rule("HOST", "citibank.com")
        r_kw_bank = Rule("HOST-KEYWORD", "citibank")
        custom_policy = dict(POLICY)
        custom_policy["domain_exclusions"] = [".citibank.com."]
        custom_policy["keyword_allowlist"] = [{"id": "kw-citibank", "value": "citibank", "category": "sdk", "note": "x", "evidence": "x"}]

        res_dns = result("BlockDNS", "dns_bypass", [r_dns_bank])
        res_kw = result("privacy", "tracking", [r_kw_bank])
        profiles, decisions = build_profiles([res_dns, res_kw], custom_policy)

        # Exclusion should take precedence over DNS bypass
        for name, profile in profiles.items():
            self.assertNotIn(r_dns_bank, profile)
            self.assertNotIn(r_kw_bank, profile)
        self.assertEqual(decisions[r_dns_bank], ("dropped", "domain_exclusion:citibank.com"))
        self.assertEqual(decisions[r_kw_bank], ("dropped", "domain_exclusion:citibank"))

    def test_load_config_with_exclusions(self):
        from rules.config import load_config
        config = load_config(ROOT)
        self.assertIn("domain_exclusions", config.policy)
        self.assertIn("getui.com", config.policy["domain_exclusions"])
        self.assertIn("collect.alipay.com", config.policy["domain_exclusions"])

    def test_ip_cidr_subnet_reduction(self):
        from rules.pipeline import _reduce
        r_parent = Rule("IP-CIDR", "10.0.0.0/8")
        r_child = Rule("IP-CIDR", "10.1.0.0/16")
        r_other = Rule("IP-CIDR", "192.168.1.0/24")
        r_reserved_child = Rule("IP-CIDR", "10.2.0.0/16")

        reduced = _reduce({r_parent, r_child, r_other, r_reserved_child}, reserved={r_reserved_child})
        self.assertIn(r_parent, reduced)
        self.assertNotIn(r_child, reduced)
        self.assertIn(r_other, reduced)
        self.assertIn(r_reserved_child, reduced)

    def test_fetch_candidate_fallback_urls(self):
        from rules.fetch import _candidate_urls
        from rules.models import SourceConfig
        source_raw = SourceConfig("test", "https://raw.githubusercontent.com/owner/repo/main/path/rule.list?token=abc", "tracking", "trusted", True, ("raw.githubusercontent.com", "cdn.jsdelivr.net"), 1000, 1000)
        urls = _candidate_urls(source_raw)
        self.assertEqual(len(urls), 2)
        self.assertEqual(urls[0], "https://raw.githubusercontent.com/owner/repo/main/path/rule.list?token=abc")
        self.assertEqual(urls[1], "https://cdn.jsdelivr.net/gh/owner/repo@main/path/rule.list?token=abc")

    def test_smooth_bracket_elastic_admission(self):
        # 3 rules of identical tier & evidence grade: bracket should finish smoothly past target into buffer
        r1 = Rule("HOST-SUFFIX", "tracker.alpha.com")
        r2 = Rule("HOST-SUFFIX", "tracker.beta.com")
        r3 = Rule("HOST-SUFFIX", "tracker.gamma.com")
        # 1 lower-ranked rule (different bracket)
        r_low = Rule("HOST", "other.delta.com")

        custom_policy = dict(POLICY)
        custom_policy["domain_evidence_catalog"] = []
        # target=2, max=5. Buffer allows 2 + max(1, int(2*0.15)) = 3 rules.
        custom_policy["profile_limits"] = {
            "clash_full": {"target": 10, "max": 20},
            "qx_universal": {"target": 10, "max": 20},
            "qx_compact": {"target": 2, "max": 5}
        }
        res = result("privacy", "tracking", [r1, r2, r3, r_low])
        profiles, decisions = build_profiles([res], custom_policy)
        compact = profiles["qx_compact"]
        # r1, r2, r3 share the same bracket and must ALL be smoothly admitted (count=3 <= soft_cap 3)
        self.assertIn(r1, compact)
        self.assertIn(r2, compact)
        self.assertIn(r3, compact)
        # r_low is in a lower bracket and target was reached, so it must NOT be admitted
        self.assertNotIn(r_low, compact)

    def test_mobile_sdk_priority_in_compact(self):
        # In QX compact, mobile SDK rule has higher evidence grade than generic tracker/metric
        # Even if mobile SDK rule has longer domain name or later alphabetical letter
        r_sdk = Rule("HOST-SUFFIX", "sensorsdata.z-long-corp-name.com")
        r_generic = Rule("HOST-SUFFIX", "tracker.a.com")

        custom_policy = dict(POLICY)
        custom_policy["domain_evidence_catalog"] = []
        custom_policy["mobile_sdk_labels"] = ["sensorsdata"]
        custom_policy["profile_limits"] = {
            "clash_full": {"target": 10, "max": 20},
            "qx_universal": {"target": 10, "max": 20},
            "qx_compact": {"target": 1, "max": 2}
        }
        res = result("privacy", "tracking", [r_sdk, r_generic])
        profiles, decisions = build_profiles([res], custom_policy)
        compact = profiles["qx_compact"]
        # r_sdk has mobile_sdk evidence grade (51) > tracker (41), so with target=1, r_sdk MUST be admitted
        self.assertIn(r_sdk, compact)
        self.assertNotIn(r_generic, compact)

    def test_ip_cidr_trusted_source_channel(self):
        """IP-CIDR from advertising source must pass through."""
        r_ip = Rule("IP-CIDR", "1.2.3.4/32")
        r_ip6 = Rule("IP6-CIDR", "2001:db8::/32")
        custom_policy = dict(POLICY)
        custom_policy["domain_evidence_catalog"] = []
        profiles, decisions = build_profiles([result("adlite", "advertising", [r_ip, r_ip6])], custom_policy)
        self.assertIn(r_ip, profiles["clash_full"])
        self.assertIn(r_ip6, profiles["clash_full"])

    def test_keyword_root_pattern_admission(self):
        """Plain ad-root keyword matching keyword_root_patterns must be admitted to Tier 1."""
        kw_adservice = Rule("HOST-KEYWORD", "adservice")
        kw_random = Rule("HOST-KEYWORD", "xjkqwerty")
        custom_policy = dict(POLICY)
        custom_policy["domain_evidence_catalog"] = []
        custom_policy["keyword_root_patterns"] = ["^adservice$"]
        profiles, _ = build_profiles([result("adlite", "advertising", [kw_adservice, kw_random])], custom_policy)
        self.assertIn(kw_adservice, profiles["clash_full"])
        self.assertNotIn(kw_random, profiles["clash_full"])

    def test_registrable_domain_consensus_scoring(self):
        """Rules sharing the same registrable domain across multiple sources get higher rd_source_count."""
        r_multi = Rule("HOST-SUFFIX", "tracker.multi-source-domain.com")
        r_single = Rule("HOST-SUFFIX", "tracker.single-source-domain.com")
        custom_policy = dict(POLICY)
        custom_policy["domain_evidence_catalog"] = []
        custom_policy["profile_limits"] = {
            "clash_full": {"target": 1, "max": 2},
            "qx_universal": {"target": 1, "max": 2},
            "qx_compact": {"target": 1, "max": 2}
        }
        res1 = result("source1", "advertising", [r_multi, r_single])
        res2 = result("source2", "tracking", [Rule("HOST", "ad.multi-source-domain.com")])
        profiles, _ = build_profiles([res1, res2], custom_policy)
        self.assertIn(r_multi, profiles["qx_compact"])
        self.assertNotIn(r_single, profiles["qx_compact"])

    def test_processor_identity_covers_rules_directory(self):
        from process_rules import processor_identity
        ident = processor_identity(ROOT)
        self.assertEqual(len(ident), 64)

    def test_fetch_extract_repo_identity(self):
        from rules.fetch import _extract_repo_identity
        self.assertEqual(_extract_repo_identity("https://raw.githubusercontent.com/owner/repo/main/path/rule.list"), "owner/repo")
        self.assertEqual(_extract_repo_identity("https://cdn.jsdelivr.net/gh/owner/repo@main/path/rule.list"), "owner/repo")
        self.assertIsNone(_extract_repo_identity("https://example.com/some/path"))

    def test_private_and_bogus_ip_cidr_rejected(self):
        from rules.normalize import normalize_ip
        # Private LAN networks
        self.assertEqual(normalize_ip("10.72.25.0/24", 4), (None, "private_or_reserved_cidr"))
        self.assertEqual(normalize_ip("192.168.1.1/32", 4), (None, "private_or_reserved_cidr"))
        self.assertEqual(normalize_ip("172.16.0.0/16", 4), (None, "private_or_reserved_cidr"))
        self.assertEqual(normalize_ip("127.0.0.1/32", 4), (None, "private_or_reserved_cidr"))
        # Broad or reserved
        self.assertEqual(normalize_ip("0.0.0.1/32", 4), (None, "private_or_reserved_cidr"))
        self.assertEqual(normalize_ip("0.0.0.0/0", 4), (None, "private_or_reserved_cidr"))
        # Valid public IP
        self.assertEqual(normalize_ip("101.124.19.122/32", 4), ("101.124.19.122/32", None))

    def test_jpush_excluded_by_domain_exclusions(self):
        r_jpush = Rule("HOST-SUFFIX", "jpush.cn")
        r_sis = Rule("HOST-SUFFIX", "sis.jpush.io")
        custom_policy = dict(POLICY)
        custom_policy["domain_exclusions"] = ["jpush.cn", "jpush.io"]
        profiles, decisions = build_profiles([result("adlite", "advertising", [r_jpush, r_sis])], custom_policy)
        for name in ("clash_full", "qx_universal", "qx_compact"):
            self.assertNotIn(r_jpush, profiles[name])
            self.assertNotIn(r_sis, profiles[name])

    def test_keyword_substring_blocked_by_domain_exclusions(self):
        # HOST-KEYWORD / DOMAIN-KEYWORD is a substring match in clients; non-dot-delimited substrings must also be blocked
        r_kw_sub = Rule("HOST-KEYWORD", "alipay")
        r_kw_partial = Rule("HOST-KEYWORD", "getui")
        r_kw_non_dot = Rule("HOST-KEYWORD", "getu")
        custom_policy = dict(POLICY)
        custom_policy["domain_exclusions"] = ["collect.alipay.com", "getui.com"]
        custom_policy["keyword_allowlist"] = [
            {"id": "kw-1", "value": "alipay", "category": "sdk", "note": "x", "evidence": "x"},
            {"id": "kw-2", "value": "getui", "category": "sdk", "note": "x", "evidence": "x"},
            {"id": "kw-3", "value": "getu", "category": "sdk", "note": "x", "evidence": "x"},
        ]
        profiles, decisions = build_profiles([result("privacy", "tracking", [r_kw_sub, r_kw_partial, r_kw_non_dot])], custom_policy)
        for kw in (r_kw_sub, r_kw_partial, r_kw_non_dot):
            self.assertNotIn(kw, profiles["clash_full"])
            self.assertTrue(decisions[kw][1].startswith("domain_exclusion:"))

    def test_dynamic_suffix_folding_frees_capacity_budget(self):
        # r_sub (HOST) has 2-source consensus -> admitted before r_parent (HOST-SUFFIX) which has 1-source
        # Once r_parent is admitted, r_sub is dynamically folded, freeing the slot for r_other within target=2!
        r_sub = Rule("HOST", "sub.tracker.example.com")
        r_parent = Rule("HOST-SUFFIX", "tracker.example.com")
        r_other = Rule("HOST-SUFFIX", "tracker.other.com")
        custom_policy = dict(POLICY)
        custom_policy["domain_evidence_catalog"] = []
        custom_policy["profile_limits"] = {
            "clash_full": {"target": 10, "max": 20},
            "qx_universal": {"target": 10, "max": 20},
            "qx_compact": {"target": 2, "max": 2},
        }
        res1 = result("privacy", "tracking", [r_sub, r_parent, r_other], consensus=True)
        res2 = result("adlite", "advertising", [r_sub], consensus=True)
        profiles, _ = build_profiles([res1, res2], custom_policy)
        compact = profiles["qx_compact"]
        self.assertIn(r_parent, compact)
        self.assertIn(r_other, compact)
        self.assertNotIn(r_sub, compact)


if __name__ == "__main__": unittest.main()
