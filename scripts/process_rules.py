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

# 2026 主流 App 关键字（用于高频置顶排序，Mac 版的核心保留项）
HOT_DOMAINS = [
    'apple.com', 'google.com', 'facebook.com', 'instagram.com', 'twitter.com', 'x.com',
    'youtube.com', 'telegram.org', 'tiktok.com', 'openai.com', 'deepseek.com',
    'tencent.com', 'alipay.com', 'taobao.com', 'byteimg.com', 'douyin.com',
    'baidu.com', 'weibo.com', 'jd.com', 'meituan.com', 'xiaohongshu.com',
    'bilibili.com', 'zhihu.com', 'iqiyi.com', 'youku.com', 'netease.com'
]

# 深度精简：剔除非主流地区后缀和极低频埋点关键词
DISCARD_LIST = [
    # 后缀精简：剔除非主要目标地区
    '.ru', '.ir', '.vn', '.br', '.in', '.ua', '.tr', '.cz', '.es', '.ma', '.no', '.pl',
    '.it', '.nl', '.fr', '.au', '.mx', '.de', '.se', '.dk', '.ch', '.be', '.at',
    # 关键词精简：剔除极其细碎的统计/日志（已涵盖在主流规则中）
    'tracking', 'telemetry', 'statistics', 'metrics', 'logging', 'crashlytics',
    'bugly', 'sensorsdata', 'umeng', 'adjust.com', 'amplitude', 'inspectlet'
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
            
            # 初步过滤
            line_lower = line.lower()
            if any(d in line_lower for d in DISCARD_LIST):
                continue
                
            parts = [p.strip() for p in line.split(',')]
            if len(parts) >= 2:
                new_rule = f"{parts[0]},{parts[1]},{POLICY_NAME}"
                if "no-resolve" in line_lower:
                    new_rule += ",no-resolve"
                rules.append(new_rule)
        return rules
    except: return []

def aggressive_optimize(rules, is_mac=False):
    """
    更激进的优化逻辑
    """
    rules = list(set(rules))
    suffixes = {r.split(',')[1] for r in rules if r.startswith('HOST-SUFFIX')}
    
    final = []
    for r in rules:
        parts = r.split(',')
        rtype, rval = parts[0], parts[1]
        rval_lower = rval.lower()
        
        # 1. 后缀冗余判定
        if rtype == 'HOST':
            if any(rval_lower.endswith("." + s) or rval_lower == s for s in suffixes):
                continue
        
        # 2. 长度过滤：将门槛降至 45，剔除大量垃圾域名
        if len(rval) > 45:
            continue
            
        # 3. Mac 特殊精简：如果不是主流域名，且不包含核心拦截词，则剔除
        if is_mac:
            is_hot = any(hot in rval_lower for hot in HOT_DOMAINS)
            is_core_ad = any(kw in rval_lower for kw in ['ad', 'track', 'log', 'stat'])
            if not (is_hot or is_core_ad):
                continue

        final.append(r)

    # 排序：主流应用排最前
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

    print("Fetching raw data...")
    raw = fetch_rules(SOURCES["privacy"]) + fetch_rules(SOURCES["adlite"])
    
    # 手机版优化
    print("Optimizing for Mobile...")
    mobile_optimized = aggressive_optimize(raw, is_mac=False)
    with open(os.path.join(args.output_dir, "Mobile_Unified.list"), "w") as f:
        f.write(generate_header("Mobile_Unified", mobile_optimized) + "\n".join(mobile_optimized))

    # Mac 版优化（采用更激进的策略）
    print("Optimizing for Mac...")
    mac_optimized = aggressive_optimize(raw, is_mac=True)
    with open(os.path.join(args.output_dir, "Mac_Unified.list"), "w") as f:
        f.write(generate_header("Mac_Unified", mac_optimized) + "\n".join(mac_optimized))
    
    print(f"Done! Mobile: {len(mobile_optimized)}, Mac: {len(mac_optimized)}")

if __name__ == "__main__":
    main()
