import requests
import argparse
import os
import sys
from datetime import datetime
import tempfile
import shutil
import re
import json
from concurrent.futures import ThreadPoolExecutor

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
    'youtube.com', 'telegram.org', 'tiktok.com', 'openai.com', 'deepseek.com', 'spotify.com',
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
    """流式获取规则，提取 TOTAL 字段，失败返回 None"""
    types = tuple(RULE_PRIORITY.keys())
    rules = []
    total_in_header = None
    try:
        with requests.get(url, timeout=30, stream=True) as r:
            r.raise_for_status()
            for line in r.iter_lines(decode_unicode=True):
                if not line: continue
                line = line.strip()
                
                # 提取 # TOTAL: 数字
                if line.startswith("# TOTAL:"):
                    match = re.search(r'# TOTAL:\s*(\d+)', line)
                    if match:
                        total_in_header = int(match.group(1))
                
                if not line.startswith(types):
                    continue
                
                parts = [p.strip() for p in line.split(',')]
                if len(parts) >= 2:
                    new_rule = f"{parts[0]},{parts[1]},{POLICY_NAME}"
                    if "no-resolve" in line.lower():
                        new_rule += ",no-resolve"
                    rules.append(new_rule)
        
        # 如果 Header 里没有 TOTAL，则使用列表长度
        final_total = total_in_header if total_in_header is not None else len(rules)
        return rules, final_total
    except requests.exceptions.RequestException as e:
        print(f"Error fetching {url}: {e}", file=sys.stderr)
        return None, None

def extreme_optimize(rules, is_mac=False):
    """极度精简算法：嵌套后缀去重与正则加速匹配"""
    # 1. 初步清理并去重
    rules = list(set(rules))
    
    # 2. 提取并排序后缀 (从短到长，用于覆盖检测)
    raw_suffixes = sorted({r.split(',')[1] for r in rules if r.startswith('HOST-SUFFIX')}, key=len)
    
    # 3. 嵌套后缀去重 (例如 google.com 覆盖 ads.google.com)
    final_suffixes = []
    for s in raw_suffixes:
        if not any(s.endswith("." + fs) for fs in final_suffixes):
            final_suffixes.append(s)
    
    suffix_set = set(final_suffixes)
    
    # 4. 正则预编译关键词过滤
    ad_pattern = re.compile('|'.join(CORE_AD_KEYWORDS), re.I)
    
    final = []
    for r in rules:
        parts = r.split(',')
        rtype, rval = parts[0], parts[1]
        rval_lower = rval.lower()
        
        if not rval_lower.endswith(ALLOWED_TLD): continue
        if len(rval) > 35: continue

        # HOST 去重 (已被后缀覆盖)
        if rtype == 'HOST':
            if any(rval_lower.endswith("." + s) or rval_lower == s for s in suffix_set):
                continue
        
        # 嵌套后缀去重 (剔除冗余后缀)
        if rtype == 'HOST-SUFFIX' and rval not in suffix_set:
            continue
        
        is_hot = any(hot in rval_lower for hot in HOT_DOMAINS)
        is_ad_kw = bool(ad_pattern.search(rval_lower))
        
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

CACHE_FILE = "scripts/rule_cache.json"

class RuleCache:
    def __init__(self, file_path):
        self.file_path = file_path
        self.data = self._load()

    def _load(self):
        if os.path.exists(self.file_path):
            try:
                with open(self.file_path, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except:
                pass
        return {"sources": {}, "consecutive_unchanged_days": 0, "last_run_date": None}

    def save(self):
        with open(self.file_path, 'w', encoding='utf-8') as f:
            json.dump(self.data, f, indent=2, ensure_ascii=False)

    def should_skip(self, current_totals):
        today = datetime.now().strftime('%Y-%m-%d')
        
        # 检查是否满 30 天
        if self.data.get("consecutive_unchanged_days", 0) >= 30:
            return False

        # 检查所有 source 是否一致
        for name, total in current_totals.items():
            prev = self.data["sources"].get(name, {}).get("last_total")
            if prev != total:
                return False
        
        return True

    def update(self, current_totals, is_changed):
        today = datetime.now().strftime('%Y-%m-%d')
        if not is_changed:
            self.data["consecutive_unchanged_days"] = self.data.get("consecutive_unchanged_days", 0) + 1
        else:
            self.data["consecutive_unchanged_days"] = 0
            
        self.data["last_run_date"] = today
        for name, total in current_totals.items():
            self.data["sources"][name] = {"last_total": total, "updated_at": today}
        self.save()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output_dir', default='dist')
    parser.add_argument('--force', action='store_true', help='Force a full update (bypass cache)')
    args = parser.parse_args()

    output_dir = os.path.abspath(args.output_dir)
    if not output_dir.startswith(os.getcwd()):
        print(f"Error: Output directory {output_dir} is outside of current workspace.")
        sys.exit(1)
    os.makedirs(output_dir, exist_ok=True)

    cache = RuleCache(os.path.join(os.getcwd(), CACHE_FILE))
    
    print(f"Fetching raw data (Parallel)... {'[FORCE MODE]' if args.force else ''}")
    source_rules = {}
    source_totals = {}
    
    def fetch_task(name_url):
        name, url = name_url
        return name, fetch_rules(url)

    with ThreadPoolExecutor(max_workers=len(SOURCES)) as executor:
        results = list(executor.map(fetch_task, SOURCES.items()))

    all_raw = []
    for name, (data, total) in results:
        if data is None:
            print(f"CRITICAL: Failed to fetch {name}. Aborting.")
            sys.exit(1)
        source_rules[name] = set(data)
        source_totals[name] = total
        all_raw.extend(data)
    
    # 缓存检查 (增加 --force 支持)
    is_forced = args.force or cache.data.get("consecutive_unchanged_days", 0) >= 30
    if cache.should_skip(source_totals) and not is_forced:
        print(f"Skipping: All sources unchanged and within 30 days ({cache.data.get('consecutive_unchanged_days')} days).")
        cache.update(source_totals, is_changed=False)
        return

    if not all_raw:
        sys.exit(1)

    print("Optimizing and Sorting...")
    if is_forced:
        print("Update triggered: Force mode or 30 days limit reached.")
    
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

    cache.update(source_totals, is_changed=True)
    print("Success!")

if __name__ == "__main__":
    main()
