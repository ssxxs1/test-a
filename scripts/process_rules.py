import requests
import argparse
import os
import sys
from datetime import datetime
import tempfile
import shutil

# 配置项
POLICY_NAME = "Advertising"
SOURCES = {
    "privacy": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/QuantumultX/Privacy/Privacy.list",
    "adlite": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/QuantumultX/AdvertisingLite/AdvertisingLite.list"
}

# 规则优先级
RULE_PRIORITY = {
    'HOST': 1,
    'HOST-SUFFIX': 2,
    'HOST-KEYWORD': 3,
    'GEOIP': 4,
    'IP-CIDR': 4,
    'IP6-CIDR': 4,
    'USER-AGENT': 5,
}

# 核心保留：主流互联网厂商域名
HOT_DOMAINS = [
    'apple.com', 'google.com', 'facebook.com', 'instagram.com', 'twitter.com', 'x.com',
    'youtube.com', 'telegram.org', 'tiktok.com', 'openai.com', 'deepseek.com',
    'tencent.com', 'alipay.com', 'taobao.com', 'byteimg.com', 'douyin.com',
    'baidu.com', 'weibo.com', 'jd.com', 'meituan.com', 'xiaohongshu.com',
    'bilibili.com', 'zhihu.com', 'iqiyi.com', 'youku.com', 'netease.com',
    'doubleclick.net', 'googleads', 'googletagmanager', 'app-measurement'
]

# 允许保留的主流 TLD
ALLOWED_TLD = (
    '.com', '.cn', '.net', '.org', '.tv', '.me', '.io', '.cc', 
    '.hk', '.jp', '.sg', '.us', '.tw', '.edu', '.gov'
)

# 核心广告关键词
CORE_AD_KEYWORDS = ['ad', 'track', 'log', 'stat', 'api', 'analytics', 'report', 'metrics']

def fetch_rules(url):
    """流式获取规则，失败返回 None 以触发熔断保护"""
    types = tuple(RULE_PRIORITY.keys())
    rules = []
    try:
        with requests.get(url, timeout=30, stream=True) as r:
            r.raise_for_status()
            for line in r.iter_lines(decode_unicode=True):
                if not line: continue
                line = line.strip()
                if not line.startswith(types):
                    continue
                
                parts = [p.strip() for p in line.split(',')]
                if len(parts) >= 2:
                    new_rule = f"{parts[0]},{parts[1]},{POLICY_NAME}"
                    if "no-resolve" in line.lower():
                        new_rule += ",no-resolve"
                    rules.append(new_rule)
        return rules
    except requests.exceptions.RequestException as e:
        print(f"Error fetching {url}: {e}", file=sys.stderr)
        return None

def extreme_optimize(rules, is_mac=False):
    """精简逻辑并按要求排序"""
    rules = list(set(rules))
    suffixes = {r.split(',')[1] for r in rules if r.startswith('HOST-SUFFIX')}
    
    final = []
    for r in rules:
        parts = r.split(',')
        rtype, rval = parts[0], parts[1]
        rval_lower = rval.lower()
        
        if not rval_lower.endswith(ALLOWED_TLD): continue
        if len(rval) > 35: continue

        if rtype == 'HOST':
            if any(rval_lower.endswith("." + s) or rval_lower == s for s in suffixes):
                continue
        
        is_hot = any(hot in rval_lower for hot in HOT_DOMAINS)
        is_ad_kw = any(kw in rval_lower for kw in CORE_AD_KEYWORDS)
        
        if is_mac:
            if not is_hot and not (is_ad_kw and rtype == 'HOST-SUFFIX'):
                continue
        else:
            if not (is_hot or is_ad_kw):
                continue
        final.append(r)

    def sort_key(rule):
        rtype = rule.split(',')[0]
        priority = RULE_PRIORITY.get(rtype, 99)
        return (priority, rule.lower())

    return sorted(final, key=sort_key)

def generate_header(name, rules, source_counts=None):
    counts = {t: 0 for t in RULE_PRIORITY.keys()}
    for r in rules:
        rtype = r.split(',')[0]
        if rtype in counts:
            counts[rtype] += 1
            
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    header = [
        f"# NAME: {name}", f"# UPDATED: {now}",
        f"# HOST: {counts.get('HOST', 0)}", 
        f"# HOST-SUFFIX: {counts.get('HOST-SUFFIX', 0)}",
        f"# HOST-KEYWORD: {counts.get('HOST-KEYWORD', 0)}",
        f"# IP-CIDR: {counts.get('IP-CIDR', 0) + counts.get('IP6-CIDR', 0)}",
        f"# TOTAL: {len(rules)}"
    ]
    
    # 动态展示所有数据源的保留条数
    if source_counts:
        for s_key in SOURCES.keys():
            count = source_counts.get(s_key, 0)
            header.append(f"# RETAINED-{s_key.upper()}: {count}")
        
    return "\n".join(header) + "\n"

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output_dir', default='dist')
    args = parser.parse_args()

    output_dir = os.path.abspath(args.output_dir)
    if not output_dir.startswith(os.getcwd()):
        print(f"Error: Output directory {output_dir} is outside of current workspace.")
        sys.exit(1)
    os.makedirs(output_dir, exist_ok=True)

    print("Fetching raw data...")
    source_rules = {}
    all_raw = []
    for name, url in SOURCES.items():
        data = fetch_rules(url)
        if data is None:
            print(f"CRITICAL: Failed to fetch {name}. Aborting.")
            sys.exit(1)
        source_rules[name] = set(data)
        all_raw.extend(data)
    
    if not all_raw:
        sys.exit(1)

    print("Optimizing and Sorting...")
    
    files_to_write = {
        "Mobile_Unified.list": extreme_optimize(all_raw, is_mac=False),
        "Mac_Unified.list": extreme_optimize(all_raw, is_mac=True)
    }

    for filename, optimized_rules in files_to_write.items():
        filepath = os.path.join(output_dir, filename)
        
        source_counts = {}
        for s_name, s_set in source_rules.items():
            source_counts[s_name] = sum(1 for r in optimized_rules if r in s_set)

        fd, temp_path = tempfile.mkstemp(dir=output_dir, text=True)
        try:
            with os.fdopen(fd, 'w') as tf:
                tf.write(generate_header(filename.split('.')[0], optimized_rules, source_counts))
                tf.write("\n".join(optimized_rules))
            
            shutil.move(temp_path, filepath)
            print(f"Saved {filename}: {len(optimized_rules)} rules")
        except Exception as e:
            print(f"Error saving {filename}: {e}")
            if os.path.exists(temp_path):
                os.remove(temp_path)
            sys.exit(1)

    print("Success!")

if __name__ == "__main__":
    main()
