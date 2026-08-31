# Rule Processing Report

## Output rules

- `clash_full`: actual=3972, target=12000, max=20000; reserved DNS=64; eligible=3961
  - tiers: tier1_eligible=78, tier1_selected=78, tier2_eligible=3852, tier2_selected=3852, tier3_eligible=31, tier3_selected=31
  - HOST=246, HOST-SUFFIX=3698, IP-CIDR=24, IP6-CIDR=4
- `qx_universal`: actual=3717, target=10000, max=20000; reserved DNS=64; eligible=3685
  - tiers: tier1_eligible=27, tier1_selected=27, tier2_eligible=3648, tier2_selected=3648, tier3_eligible=10, tier3_selected=10
  - HOST=231, HOST-SUFFIX=3458, IP-CIDR=24, IP6-CIDR=4
- `qx_compact`: actual=1969, target=2000, max=5000; reserved DNS=64; eligible=3361
  - tiers: tier1_eligible=61, tier1_selected=61, tier2_eligible=3300, tier2_selected=1875
  - HOST=92, HOST-SUFFIX=1849, IP-CIDR=24, IP6-CIDR=4

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
