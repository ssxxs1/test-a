# Rule Processing Report

## Output rules

- `clash_full`: actual=4182, target=12000, max=20000; reserved DNS=64; eligible=4190
  - tiers: tier1_eligible=141, tier1_selected=118, tier2_eligible=4018, tier2_selected=3969, tier3_eligible=31, tier3_selected=30
  - HOST=240, HOST-KEYWORD=21, HOST-SUFFIX=3699, IP-CIDR=218, IP6-CIDR=4
- `qx_universal`: actual=3936, target=10000, max=20000; reserved DNS=64; eligible=3912
  - tiers: tier1_eligible=87, tier1_selected=72, tier2_eligible=3815, tier2_selected=3791, tier3_eligible=10, tier3_selected=10
  - HOST=235, HOST-KEYWORD=21, HOST-SUFFIX=3458, IP-CIDR=218, IP6-CIDR=4
- `qx_compact`: actual=2279, target=2000, max=5000; reserved DNS=64; eligible=3572
  - tiers: tier1_eligible=110, tier1_selected=90, tier2_eligible=3462, tier2_selected=2125
  - HOST=83, HOST-KEYWORD=21, HOST-SUFFIX=2147, IP-CIDR=24, IP6-CIDR=4

## BlockDNS passthrough

- Normalized source rules: 64
- `clash_full` retained: 64/64
- `qx_universal` retained: 64/64
- `qx_compact` retained: 64/64

## Sources

- `privacy`: candidates=39936, parsed=39933, canonical=f8d1fd3c8007cfa4e31a06ae01d2cb407d463f2aba85e10de173dcb7f86009c5
- `adlite`: candidates=38066, parsed=38052, canonical=6331dfe05ef2b38a014872038a62fe5ac265ea46f7e1436f3956965f5c6db66e
- `BlockDNS`: candidates=64, parsed=64, canonical=1b8ab6e4d4fa867761d5ebdf793bb21659c2ef3c25c6b46d1f4edb0c31dd7373

## Safety rejections

- `keyword_too_short`: 1
- `private_or_reserved_cidr`: 2
- `psl_unknown_suffix`: 9
- `public_suffix_root`: 5
