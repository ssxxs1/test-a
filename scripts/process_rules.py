import requests
import argparse
import os
from datetime import datetime

# 配置项
POLICY_NAME = "Advertising"
SOURCES = {
    "privacy": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/QuantumultX/Privacy/Privacy.list",
    "adlite": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/QuantumultX/AdvertisingLite/AdvertisingLite.list"
}

# 2026 主流 App 关键字（用于高频置顶排序）
HOT_DOMAINS = [
    'apple.com', 'google.com', 'facebook.com', 'instagram.com', 'twitter.com', 'x.com',
    'youtube.com', 'telegram.org', 'tiktok.com', 'openai.com', 'deepseek.com',
    'tencent.com', 'alipay.com', 'taobao.com', 'byteimg.com', 'douyin.com'
]
# 剔除列表：不常访问的地区和冗余服务（精简核心）
DISCARD_LIST = [
    '.ru', '.ir', '.vn', '.br', '.in', '.ua', '.tr', # 剔除非目标地区后缀
    'tracking', 'telemetry', 'analytics', 'statistics', # 剔除过分细碎的埋点（已包含在主流规则中）
    'metrics', 'logging', 'crashlytics'
]

def fetch_rules(url):
    try:
        r = requests.get(url, timeout=30)
        types = ('HOST', 'HOST-SUFFIX', 'HOST-KEYWORD', 'IP-CIDR', 'IP6-CIDR')
        rules = []
        for line in r.text.split('\n'):
            line = line.strip()
            if not line.startswith(types):
                continue
            
            # 逻辑精简：如果包含不常访问的后缀，直接丢弃
            if any(d in line.lower() for d in DISCARD_LIST):
                continue
                
            parts = [p.strip() for p in line.split(',')]
            if len(parts) >= 2:
                new_rule = f"{parts[0]},{parts[1]},{POLICY_NAME}"
                if "no-resolve" in line.lower():
                    new_rule += ",no-resolve"
                rules.append(new_rule)
        return rules
    except: return []

def aggressive_optimize(rules):
    """激进优化：去重、后缀压缩、排序"""
    rules = list(set(rules))
    
    # 提取所有后缀
    suffixes = {r.split(',')[1] for r in rules if r.startswith('HOST-SUFFIX')}
    
    final = []
    for r in rules:
        parts = r.split(',')
        rtype, rval = parts[0], parts[1]
        
        # 1. 后缀包含判定：如果已有后缀拦截，删除具体的 HOST 拦截
        if rtype == 'HOST':
            if any(rval.endswith("." + s) or rval == s for s in suffixes):
                continue
        
        # 2. 长度过滤：剔除异常长的域名（通常是动态生成的广告位，命中率极低）
        if len(rval) > 60:
            continue
            
        final.append(r)

    # 排序逻辑：将 HOT_DOMAINS 相关规则排在最前面
    return sorted(final, key=lambda x: not any(hot in x.lower() for hot in HOT_DOMAINS))

def generate_header(name, rules):
    counts = {
        'HOST': 0,
        'HOST-KEYWORD': 0,
        'HOST-SUFFIX': 0,
        'IP-CIDR': 0,
        'IP6-CIDR': 0
    }
    for r in rules:
        for t in counts.keys():
            if r.startswith(t + ','):
                counts[t] += 1
                break
    
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    header = [
        f"# NAME: {name}",
        f"# UPDATED: {now}",
        f"# HOST: {counts['HOST']}",
        f"# HOST-KEYWORD: {counts['HOST-KEYWORD']}",
        f"# HOST-SUFFIX: {counts['HOST-SUFFIX']}",
        f"# IP-CIDR: {counts['IP-CIDR']}",
        f"# IP6-CIDR: {counts['IP6-CIDR']}",
        f"# TOTAL: {len(rules)}"
    ]
    return "\n".join(header) + "\n"

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output_dir', default='dist')
    args = parser.parse_args()
    os.makedirs(args.output_dir, exist_ok=True)

    print("Fetching and Pruning...")
    raw = fetch_rules(SOURCES["privacy"]) + fetch_rules(SOURCES["adlite"])
    optimized = aggressive_optimize(raw)

    # 手机版：精简后的全量
    with open(os.path.join(args.output_dir, "Mobile_Unified.list"), "w") as f:
        f.write(generate_header("Mobile_Unified", optimized) + "\n".join(optimized))

    # Mac 版：更激进的精简（仅保留主流域名相关的拦截）
    # 逻辑：对于 Mac，如果不属于 HOT_DOMAINS 且不是后缀匹配，则剔除
    mac_rules = [r for r in optimized if any(h in r.lower() for h in HOT_DOMAINS) or r.startswith('HOST-SUFFIX')]
    
    with open(os.path.join(args.output_dir, "Mac_Unified.list"), "w") as f:
        f.write(generate_header("Mac_Unified", mac_rules) + "\n".join(mac_rules))
    
    print(f"Success! Mobile: {len(optimized)}, Mac: {len(mac_rules)}")


if __name__ == "__main__":
    main()
