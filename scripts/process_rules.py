import requests
import re

# 配置源地址
SOURCES = {
    "privacy": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/QuantumultX/Privacy/Privacy.list",
    "adlite": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/QuantumultX/AdvertisingLite/AdvertisingLite.list"
}

# 必须保留的关键字（覆盖主流及 2026 趋势）
MUST_KEEP = [
    'google', 'facebook', 'instagram', 'twitter', 'youtube', 'telegram', 'tiktok', # 社交/视频
    'openai', 'chatgpt', 'anthropic', 'claude', 'gemini', 'deepseek', 'perplexity', # AI 类
    'amazon', 'netflix', 'spotify', 'disney', 'apple', 'microsoft', # 生产力/娱乐
    'taobao', 'tencent', 'alipay', 'bytedance', 'baidu', 'meituan', 'pinduoduo', 'jd.com', # 国内大厂
    'xiaohongshu', 'bilibili', 'weibo', 'amap', 'douyin' # 国内主流
]

# 排除非目标区域（减少冗余）
EXCLUDE_REGIONS = ['.ru', '.ir', '.vn', '.br', '.in'] 

def fetch_and_clean(url):
    try:
        content = requests.get(url, timeout=30).text
        lines = content.split('\n')
        # 仅保留有效的规则行
        return [l for l in lines if l.startswith(('HOST', 'HOST-SUFFIX', 'HOST-KEYWORD'))]
    except:
        return []

def compress_rules(rules):
    """简单的字典树逻辑：如果有了 .example.com，就删掉 ads.example.com"""
    rules = sorted(list(set(rules)))
    optimized = []
    suffixes = set()
    
    # 先收集所有后缀
    for r in rules:
        if r.startswith('HOST-SUFFIX'):
            suffixes.add(r.split(',')[1].strip())
    
    for r in rules:
        if r.startswith('HOST,'):
            domain = r.split(',')[1].strip()
            # 如果当前域名的后缀已经在后缀集合里，则跳过此 HOST 规则
            if any(domain.endswith("." + s) or domain == s for s in suffixes):
                continue
        optimized.append(r)
    return optimized

def main():
    print("Fetching rules...")
    raw_rules = fetch_and_clean(SOURCES["privacy"]) + fetch_and_clean(SOURCES["adlite"])
    
    # 1. 过滤掉冷门区域域名
    filtered = [r for r in raw_rules if not any(reg in r.lower() for reg in EXCLUDE_REGIONS)]
    
    # 2. 压缩去重
    compressed = compress_rules(filtered)
    
    # 3. 生成 iOS 版 (全量主流)
    # 保留包含 MUST_KEEP 关键字或原本就在列表中的高质量规则
    mobile_rules = [r for r in compressed if any(k in r.lower() for k in MUST_KEEP) or len(r) < 40]

    # 4. 生成 Mac 版 (精简掉纯移动端行为)
    # 剔除仅在手机 App 出现的特定域名（示例：部分移动支付回调、极光推送等）
    mobile_only = ['jpush', 'getui', 'mob.com', 'pinduoduo', 'pangle']
    mac_rules = [r for r in mobile_rules if not any(m in r.lower() for m in mobile_only)]

    # 5. 写入文件
    with open("dist/Mobile_Unified.list", "w") as f:
        f.write(f"# Unified Rules for iOS\n# Total: {len(mobile_rules)}\n" + "\n".join(mobile_rules))
        
    with open("dist/Mac_Unified.list", "w") as f:
        f.write(f"# Unified Rules for macOS\n# Total: {len(mac_rules)}\n" + "\n".join(mac_rules))
    print(f"Done! Mobile: {len(mobile_rules)}, Mac: {len(mac_rules)}")

if __name__ == "__main__":
    main()