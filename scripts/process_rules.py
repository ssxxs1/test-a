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
ALLOWED_TLD = ('.com', '.cn', '.net', '.org', '.tv', '.me', '.io', '.cc')

# 核心广告关键词（白名单模式）
CORE_AD_KEYWORDS = ['ad', 'track', 'log', 'stat', 'api', 'analytics', 'report', 'metrics']

def fetch_rules(url):
    try:
        r = requests.get(url, timeout=30)
        types = ('HOST', 'HOST-SUFFIX', 'HOST-KEYWORD', 'IP-CIDR', 'IP6-CIDR')
        return [l.strip() for l in r.text.split('\n') if l.startswith(types)]
    except: return []

def extreme_optimize(rules, is_mac=False):
    """
    极度精简逻辑：仅保留高频、核心规则
    """
    rules = list(set(rules))
    suffixes = {r.split(',')[1] for r in rules if r.startswith('HOST-SUFFIX')}
    
    final = []
    for r in rules:
        parts = r.split(',')
        rtype, rval = parts[0], parts[1]
        rval_lower = rval.lower()
        
        # 1. 基础过滤：后缀名必须在主流 TLD 内
        if not rval_lower.endswith(ALLOWED_TLD):
            continue
            
        # 2. 长度极限过滤：超过 35 字符的通常不具代表性
        if len(rval) > 35:
            continue

        # 3. 冗余过滤
        if rtype == 'HOST':
            if any(rval_lower.endswith("." + s) or rval_lower == s for s in suffixes):
                continue
        
        # 4. 内容过滤：精准打击核心
        is_hot = any(hot in rval_lower for hot in HOT_DOMAINS)
        is_ad_kw = any(kw in rval_lower for kw in CORE_AD_KEYWORDS)
        
        if is_mac:
            # Mac 版更严格：必须是主流厂商，或者是非常明显的 ad 后缀
            if not is_hot:
                # 如果不是主流厂商，必须包含核心 ad 关键词且是 HOST-SUFFIX
                if not (is_ad_kw and rtype == 'HOST-SUFFIX'):
                    continue
        else:
            # 手机版：保留主流厂商规则 + 包含核心关键词的规则
            if not (is_hot or is_ad_kw):
                continue

        final.append(r)

    # 排序：高频优先
    return sorted(final, key=lambda x: not any(hot in x.lower() for hot in HOT_DOMAINS))

def generate_header(name, rules):
    counts = {
        'HOST': 0, 'HOST-KEYWORD': 0, 'HOST-SUFFIX': 0, 'IP-CIDR': 0, 'IP6-CIDR': 0
    }
    for r in rules:
        for t in counts.keys():
            if r.startswith(t + ','):
                counts[t] += 1
                break
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    header = [
        f"# NAME: {name}", f"# UPDATED: {now}",
        f"# HOST: {counts['HOST']}", f"# HOST-KEYWORD: {counts['HOST-KEYWORD']}",
        f"# HOST-SUFFIX: {counts['HOST-SUFFIX']}", f"# IP-CIDR: {counts['IP-CIDR']}",
        f"# IP6-CIDR: {counts['IP6-CIDR']}", f"# TOTAL: {len(rules)}"
    ]
    return "\n".join(header) + "\n"

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output_dir', default='dist')
    args = parser.parse_args()
    os.makedirs(args.output_dir, exist_ok=True)

    print("Fetching and Pruning...")
    raw = fetch_rules(SOURCES["privacy"]) + fetch_rules(SOURCES["adlite"])
    
    # 手机版：压制到约 1.5w - 2.5w
    mobile = extreme_optimize(raw, is_mac=False)
    with open(os.path.join(args.output_dir, "Mobile_Unified.list"), "w") as f:
        f.write(generate_header("Mobile_Unified", mobile) + "\n".join(mobile))

    # Mac 版：压制到约 5000 - 1w
    mac = extreme_optimize(raw, is_mac=True)
    with open(os.path.join(args.output_dir, "Mac_Unified.list"), "w") as f:
        f.write(generate_header("Mac_Unified", mac) + "\n".join(mac))
    
    print(f"Success! Mobile: {len(mobile)}, Mac: {len(mac)}")

if __name__ == "__main__":
    main()
