# Rule Processing Report

## Output rules

- `clash_full`: actual=3972, target=12000, max=20000; reserved DNS=64; eligible=3980
  - tiers: tier1_eligible=123, tier1_selected=100, tier2_eligible=3826, tier2_selected=3777, tier3_eligible=31, tier3_selected=30
  - HOST=241, HOST-KEYWORD=2, HOST-SUFFIX=3701, IP-CIDR=24, IP6-CIDR=4
- `qx_universal`: actual=3723, target=10000, max=20000; reserved DNS=64; eligible=3699
  - tiers: tier1_eligible=68, tier1_selected=53, tier2_eligible=3621, tier2_selected=3597, tier3_eligible=10, tier3_selected=10
  - HOST=235, HOST-KEYWORD=2, HOST-SUFFIX=3458, IP-CIDR=24, IP6-CIDR=4
- `qx_compact`: actual=2000, target=2000, max=5000; reserved DNS=64; eligible=3362
  - tiers: tier1_eligible=92, tier1_selected=72, tier2_eligible=3270, tier2_selected=1864
  - HOST=79, HOST-KEYWORD=2, HOST-SUFFIX=1891, IP-CIDR=24, IP6-CIDR=4

## BlockDNS passthrough

- Normalized source rules: 64
- `clash_full` retained: 64/64
- `qx_universal` retained: 64/64
- `qx_compact` retained: 64/64

## Sources

- `privacy`: candidates=39936, parsed=39934, canonical=c240a05d77c37fe25a2d6b74a13ce3f2e90cebaca625ce0e514303b052640967
- `adlite`: candidates=38066, parsed=38053, canonical=d32687ce55f318436738dfc4e63f3ef136627cea5a747a25b73fe8fa63e6cd0d
- `BlockDNS`: candidates=64, parsed=64, canonical=1b8ab6e4d4fa867761d5ebdf793bb21659c2ef3c25c6b46d1f4edb0c31dd7373

## Safety rejections

- `keyword_too_short`: 1
- `psl_unknown_suffix`: 9
- `public_suffix_root`: 5
