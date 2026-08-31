from __future__ import annotations

import ipaddress
import re

import tldextract

from .models import Rule

EXTRACTOR = tldextract.TLDExtract(
    cache_dir=None,
    suffix_list_urls=(),
    fallback_to_snapshot=True,
    include_psl_private_domains=True,
)
HOST_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
KEYWORD = re.compile(r"^[A-Za-z0-9._-]{1,128}$")


def is_ip_literal(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def normalize_domain(value: str) -> tuple[str | None, str | None, str | None]:
    value = value.strip().lower().lstrip(".").rstrip(".")
    if not value or any(char in value for char in "/:* \\@"):
        return None, None, "invalid_domain_shape"
    if is_ip_literal(value):
        return value, None, None
    try:
        ascii_value = value.encode("idna").decode("ascii")
    except UnicodeError:
        return None, None, "invalid_idn"
    if len(ascii_value) > 253 or any(not HOST_LABEL.fullmatch(label) for label in ascii_value.split(".")):
        return None, None, "invalid_domain"
    result = EXTRACTOR(ascii_value)
    if not result.suffix:
        return None, None, "psl_unknown_suffix"
    if not result.domain:
        return None, None, "public_suffix_root"
    registrable = f"{result.domain}.{result.suffix}"
    if ascii_value == result.suffix:
        return None, None, "public_suffix_root"
    return ascii_value, registrable, None


def normalize_keyword(value: str, denylist: set[str]) -> tuple[str | None, str | None]:
    value = value.strip().lower()
    if not KEYWORD.fullmatch(value):
        return None, "invalid_keyword"
    if len(value) < 5:
        return None, "keyword_too_short"
    if value in denylist:
        return None, "keyword_denylisted"
    return value, None


def normalize_ip(value: str, expected_version: int) -> tuple[str | None, str | None]:
    try:
        network = ipaddress.ip_network(value.strip(), strict=False)
    except ValueError:
        return None, "invalid_cidr"
    if network.version != expected_version:
        return None, "cidr_version_mismatch"
    return str(network), None


def structural_random_reasons(value: str, policy: dict) -> list[str]:
    """Return deterministic generated-label indicators without matching arbitrary substrings."""
    reasons: list[str] = []
    if is_ip_literal(value):
        return reasons
    for label in value.split("."):
        length = len(label)
        digits = sum(char.isdigit() for char in label)
        if length >= policy["numeric_label_min_length"] and label.isdigit():
            reasons.append("long_numeric_label")
        elif length >= policy["hex_label_min_length"] and re.fullmatch(r"[0-9a-f]+", label):
            reasons.append("long_hex_label")
        elif length >= policy["mixed_label_min_length"] and digits / length >= policy["mixed_label_min_digit_ratio"] and re.fullmatch(r"[a-z0-9]+", label):
            reasons.append("digit_heavy_alphanumeric_label")
    return reasons


def format_rule(rule: Rule, policy: str) -> str:
    fields = [rule.rule_type, rule.value, policy]
    if "no-resolve" in rule.modifiers:
        fields.append("no-resolve")
    return ",".join(fields)


def covered_by_suffix(value: str, suffixes: set[str]) -> str | None:
    if value in suffixes:
        return value
    parts = value.split(".")
    for index in range(1, len(parts)):
        candidate = ".".join(parts[index:])
        if candidate in suffixes:
            return candidate
    return None
