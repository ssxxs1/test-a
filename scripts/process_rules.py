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

def fetch_rules(url):
    try:
        r = requests.get(url, timeout=30)
        types = ('HOST', 'HOST-SUFFIX', 'HOST-KEYWORD', 'IP-CIDR', 'IP6-CIDR')
        rules = []
        for line in r.text.split('\n'):
            line = line.strip()
            if line.startswith(types):
                parts = [p.strip() for p in line.split(',')]
                if len(parts) >= 2:
                    # 重新构造规则：类型,值,自定义策略名
                    new_rule = f"{parts[0]},{parts[1]},{POLICY_NAME}"
                    # 如果原始规则包含 no-resolve，则予以保留
                    if "no-resolve" in line.lower():
                        new_rule += ",no-resolve"
                    rules.append(new_rule)
        return rules
    except: return []

def optimize_rules(rules):
    # 简单的字典树去重逻辑
    rules = sorted(list(set(rules)))
    suffixes = {r.split(',')[1] for r in rules if r.startswith('HOST-SUFFIX')}
    final = []
    for r in rules:
        if r.startswith('HOST,'):
            domain = r.split(',')[1]
            if any(domain.endswith("." + s) or domain == s for s in suffixes):
                continue
        final.append(r)
    # 排序：高频域名排在前面，提升 QX 匹配速度
    return sorted(final, key=lambda x: not any(hot in x for hot in HOT_DOMAINS))

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
        f"# AUTHOR: blackmatrix7",
        f"# REPO: https://github.com/blackmatrix7/ios_rule_script",
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
    raw = fetch_rules(SOURCES["privacy"]) + fetch_rules(SOURCES["adlite"])
    optimized = optimize_rules(raw)

    # 分发手机版和电脑版
    with open(os.path.join(args.output_dir, "Mobile_Unified.list"), "w") as f:
        header = generate_header("Advertising", optimized)
        f.write(header + "\n".join(optimized))

    # Mac 版可进一步精简
    mac_optimized = [r for r in optimized if not any(kw in r for kw in ['jpush', 'getui', 'mob.com'])]
    with open(os.path.join(args.output_dir, "Mac_Unified.list"), "w") as f:
        header = generate_header("Advertising (Mac)", mac_optimized)
        f.write(header + "\n".join(mac_optimized))

if __name__ == "__main__":
    main()
