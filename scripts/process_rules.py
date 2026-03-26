import requests
import argparse
import os

# 配置源
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
        return [l.strip() for l in r.text.split('\n') if l.startswith(('HOST', 'HOST-SUFFIX'))]
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

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output_dir', default='dist')
    args = parser.parse_args()
    
    os.makedirs(args.output_dir, exist_ok=True)
    raw = fetch_rules(SOURCES["privacy"]) + fetch_rules(SOURCES["adlite"])
    optimized = optimize_rules(raw)

    # 分发手机版和电脑版（Mac 版剔除部分纯手机 App 埋点，减少开销）
    with open(os.path.join(args.output_dir, "Mobile_Unified.list"), "w") as f:
        f.write("# Mobile Unified Rules\n" + "\n".join(optimized))

    # Mac 版可进一步精简（例如剔除极光推送、个推等移动端专用域名）
    mac_optimized = [r for r in optimized if not any(kw in r for kw in ['jpush', 'getui', 'mob.com'])]
    with open(os.path.join(args.output_dir, "Mac_Unified.list"), "w") as f:
        f.write("# Mac Unified Rules\n" + "\n".join(mac_optimized))

if __name__ == "__main__":
    main()