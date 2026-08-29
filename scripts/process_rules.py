import requests
import argparse
import os
import sys
from datetime import datetime
import tempfile
import shutil
import re
import json
import ipaddress
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
import urllib3

urllib3.disable_warnings()

# 配置项
POLICY_NAME = "Advertising"
SOURCES = {
    "privacy": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/QuantumultX/Privacy/Privacy.list",
    "adlite": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/QuantumultX/AdvertisingLite/AdvertisingLite.list",
    "BlockDNS": "https://github.com/VirgilClyne/GetSomeFries/raw/main/ruleset/HTTPDNS.Block.list"
}
# 直通源白名单：豁免 TLD/关键词过滤，保留所有域名与 IP
PASSTHROUGH_SOURCES = {"BlockDNS"}

# 规则优先级
RULE_PRIORITY = {
    'HOST': 1,
    'HOST-SUFFIX': 2,
    'HOST-KEYWORD': 3,
    'IP-CIDR': 4,
    'IP6-CIDR': 4,
    'GEOIP': 5,
    'USER-AGENT': 6,
}

# 外部输入规则类型映射到内部标准 QX 格式
INBOUND_TYPE_MAP = {
    'DOMAIN': 'HOST',
    'DOMAIN-SUFFIX': 'HOST-SUFFIX',
    'DOMAIN-KEYWORD': 'HOST-KEYWORD',
    'HOST': 'HOST',
    'HOST-SUFFIX': 'HOST-SUFFIX',
    'HOST-KEYWORD': 'HOST-KEYWORD',
    'IP-CIDR': 'IP-CIDR',
    'IP-CIDR6': 'IP6-CIDR',
    'IP6-CIDR': 'IP6-CIDR',
    'GEOIP': 'GEOIP',
    'USER-AGENT': 'USER-AGENT',
}

# QX 到 Clash 规则转换映射
QX_TO_CLASH = {
    'HOST': 'DOMAIN',
    'HOST-SUFFIX': 'DOMAIN-SUFFIX',
    'HOST-KEYWORD': 'DOMAIN-KEYWORD',
    'IP-CIDR': 'IP-CIDR',
    'IP6-CIDR': 'IP-CIDR6',
    'GEOIP': 'GEOIP',
    'USER-AGENT': None  # Clash rule-provider 不支持 USER-AGENT
}

# 多级顶级域名定义（用于主域提取）
MULTI_PART_TLDS = (
    '.com.cn', '.net.cn', '.org.cn', '.edu.cn', '.gov.cn',
    '.co.jp', '.ne.jp', '.co.uk', '.org.uk', '.com.tw', '.org.tw',
    '.com.hk', '.org.hk', '.com.sg'
)

# 允许保留的主流 TLD
ALLOWED_TLD = (
    '.com', '.cn', '.net', '.org', '.tv', '.me', '.io', '.cc',
    '.hk', '.jp', '.sg', '.us', '.tw', '.edu', '.gov', '.vip', '.top', '.xyz'
)

# 核心广告关键词
CORE_AD_KEYWORDS = ['ad', 'track', 'log', 'stat', 'api', 'analytics', 'report', 'metrics']

# 核心保留：主流互联网厂商域名白名单/关键特征
HOT_DOMAINS = [
    'apple.com', 'google.com', 'facebook.com', 'instagram.com', 'twitter.com', 'x.com',
    'youtube.com', 'telegram.org', 'tiktok.com', 'openai.com', 'deepseek.com', 'spotify.com',
    'tencent.com', 'alipay.com', 'taobao.com', 'byteimg.com', 'douyin.com',
    'baidu.com', 'weibo.com', 'jd.com', 'meituan.com', 'xiaohongshu.com',
    'bilibili.com', 'zhihu.com', 'iqiyi.com', 'youku.com', 'netease.com',
    'doubleclick.net', 'googleads', 'googletagmanager', 'app-measurement'
]

# 移动端核心广告 SDK / 联盟 / 超级 App 开屏追踪高频特征
CORE_MOBILE_AD_NETWORKS = [
    # 顶级移动广告联盟 (穿山甲 / 优量汇 / 百度联盟 / 快手联盟)
    'pangle.io', 'pangolin-sdk', 'toblog.ctobsnssdk.com', 'ad.toutiao.com', 'dm.bytedance.com',
    'gdt.qq.com', 'e.qq.com', 'pgdt.gtimg.cn', 'adsmind.gdt.qq.com', 'ad.qq.com', 'mi.gdt.qq.com',
    'pos.baidu.com', 'cpro.baidustatic.com', 'mobads.baidu.com', 'mobads-logs.baidu.com', 'als.baidu.com',
    'e.kuaishou.com', 'ad.kuaishou.com', 'open.e.kuaishou.com',
    # 阿里妈妈 / TANX / 百川 / 营销联盟
    'tanx.com', 'alimama.com', 'adash.m.taobao.com', 'adashbc.m.taobao.com', 'adash.man.aliyuncs.com',
    'munion.com', 'mmstat.com', 'aliapp.org',
    # 移动聚合广告 SDK
    'sigmob.cn', 'mintegral.com', 'mbridge.com', 'adtiming.com', 'unityads.unity3d.com',
    'applovin.com', 'adcolony.com', 'ironsrc.com', 'vungle.com', 'inmobi.com', 'admob.com',
    'chartboost.com', 'fyber.com', 'tapjoy.com', 'smaato.net', 'pubmatic.com', 'rubiconproject.com',
    'doubleclick.net', 'googleads', 'googlesyndication.com', 'google-analytics.com', 'app-measurement.com',
    # 国内主流统计 / 埋点 / 营销推送 SDK
    'umeng.com', 'umengcloud.com', 'jpush.cn', 'jpush.io', 'jiguang.cn',
    'getui.com', 'igexin.com', 'sensorsdata.cn', 'zhugeio.com', 'talkingdata.net',
    'growingio.com', 'track.uc.cn',
    # 头部 App 移动端开屏 / 遥测 / 广告特征
    'aedns.weixin.qq.com', 'beacon.qq.com', 'oth.eve.mdt.qq.com', 'adfilter.imtt.qq.com',
    'sdkapp.uve.weibo.com', 'wbapp.uve.weibo.com', 'ad.weibo.com', 'biz.weibo.com',
    'cm.bilibili.com', 'data.bilibili.com', 'loc-api.bilibili.com',
    'analytics.meituan.net', 'log.meituan.com', 'report.meituan.com',
    'log.snssdk.com', 'mon.snssdk.com', 'ichannel.snssdk.com'
]

# 受保护的主域（禁止整域向上折叠为 HOST-SUFFIX，防止误杀大厂全量基础服务）
PROTECTED_ETLD1 = {
    'qq.com', 'tencent.com', 'gtimg.cn', 'gtimg.com', 'qpic.cn', 'qlogo.cn',
    'baidu.com', 'baidupcs.com', 'bdimg.com', 'bdstatic.com',
    'alibaba.com', 'aliyun.com', 'alicdn.com', 'taobao.com', 'alipay.com', 'tmall.com', 'tbcdn.cn',
    'bytedance.com', 'byteimg.com', 'douyin.com', 'snssdk.com', 'toutiao.com', 'pstatp.com',
    'kuaishou.com', 'yximgs.com', 'kwai.com',
    'bilibili.com', 'bilivideo.com', 'hdslb.com',
    'meituan.com', 'meituan.net', 'dianping.com',
    'jd.com', '360buy.com', '360buyimg.com',
    'weibo.com', 'sina.com.cn', 'sina.cn', 'sinaimg.cn',
    'xiaohongshu.com', 'xhscdn.com',
    'zhihu.com', 'zhimg.com',
    '163.com', '126.net', 'netease.com',
    'iqiyi.com', 'qiyi.com', 'youku.com',
    'apple.com', 'icloud.com', 'mzstatic.com',
    'google.com', 'googleapis.com', 'gstatic.com', 'youtube.com', 'googlevideo.com',
    'microsoft.com', 'azure.com', 'windows.com', 'office.com', 'live.com',
    'github.com', 'githubusercontent.com', 'github.io', 'gitlab.com',
    'amazon.com', 'aws.amazon.com', 'cloudflare.com', 'fastly.net',
    'telegram.org', 'twitter.com', 'x.com', 'facebook.com', 'instagram.com',
    'spotify.com', 'netflix.com', 'openai.com'
}


def get_etld1(domain: str) -> str:
    """提取二级主域 (eTLD+1)"""
    domain = domain.lower().strip('.')
    for mptld in MULTI_PART_TLDS:
        if domain.endswith(mptld):
            parts = domain[:-len(mptld)].split('.')
            if parts:
                return f"{parts[-1]}{mptld}"
            return domain
    parts = domain.split('.')
    if len(parts) >= 2:
        return f"{parts[-2]}.{parts[-1]}"
    return domain


def collapse_ip_rules(ip_rule_list):
    """智能合并 IPv4 / IPv6 CIDR 子网规则"""
    v4_nets = []
    v6_nets = []
    other_rules = []

    for r in ip_rule_list:
        parts = r.split(',')
        rval = parts[1]
        try:
            net = ipaddress.ip_network(rval, strict=False)
            if isinstance(net, ipaddress.IPv4Network):
                v4_nets.append(net)
            elif isinstance(net, ipaddress.IPv6Network):
                v6_nets.append(net)
            else:
                other_rules.append(r)
        except Exception:
            other_rules.append(r)

    collapsed_v4 = [f"IP-CIDR,{net},{POLICY_NAME}" for net in ipaddress.collapse_addresses(v4_nets)]
    collapsed_v6 = [f"IP6-CIDR,{net},{POLICY_NAME}" for net in ipaddress.collapse_addresses(v6_nets)]
    return sorted(list(set(collapsed_v4 + collapsed_v6 + other_rules)))


def fetch_rules(url):
    """获取规则，兼容 Surge/Clash/QX 多种语法并标准化，提取 TOTAL 字段，失败返回 None"""
    rules = []
    total_in_header = None
    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
    }
    try:
        r = requests.get(url, headers=headers, timeout=(10, 30), verify=False)
        r.raise_for_status()
        for line in r.text.splitlines():
            if not line:
                continue
            line = line.strip()

            # 提取 # TOTAL: 数字
            if line.startswith("# TOTAL:"):
                match = re.search(r'# TOTAL:\s*(\d+)', line)
                if match:
                    total_in_header = int(match.group(1))

            # 忽略纯注释或非规则行
            if line.startswith(('#', '//', '!', ';')):
                continue

            parts = [p.strip() for p in line.split(',')]
            if len(parts) < 2:
                continue

            raw_type = parts[0].upper()
            if raw_type not in INBOUND_TYPE_MAP:
                continue

            canonical_type = INBOUND_TYPE_MAP[raw_type]
            rval = parts[1]

            new_rule = f"{canonical_type},{rval},{POLICY_NAME}"
            if "no-resolve" in line.lower():
                new_rule += ",no-resolve"
            rules.append(new_rule)

        final_total = total_in_header if total_in_header is not None else len(rules)
        return rules, final_total
    except requests.exceptions.RequestException as e:
        print(f"Error fetching {url}: {e}", file=sys.stderr)
        return None, None


def is_domain_covered_by_suffix(domain: str, suffix_set: set) -> bool:
    """O(k) 复杂度判断域名是否命中后缀集合（k 为点号分段数，极速哈希匹配）"""
    d = domain.lower().strip('.')
    if d in suffix_set:
        return True
    parts = d.split('.')
    for i in range(1, len(parts)):
        parent = '.'.join(parts[i:])
        if parent in suffix_set:
            return True
    return False


def smart_optimize(regular_rules, passthrough_rules=None, is_mac=False):
    """
    智能精炼算法（零误伤安全模型）：
    1. IP-CIDR 子网智能聚合
    2. 严格按原始粒度处理（绝不随意将普通主域折叠为 HOST-SUFFIX，严防误杀大厂主站与多租户 CDN）
    3. 嵌套后缀覆盖去重 (Suffix Reduction: HOST-SUFFIX 覆盖子域名，HOST 已被 HOST-SUFFIX 覆盖则精简)
    4. 平台按需分层：
       - Mobile (极速开屏版): 核心 SDK + 头部 App 广告 + HTTPDNS + 高置信度 HOST-SUFFIX + 核心 HOST
       - Mac (全量 Web 版): 包含全量 Web 规则与长尾追踪
    """
    if passthrough_rules is None:
        passthrough_rules = []

    # 1. 拆分 IP 与 域名规则
    ip_prefixes = ('IP-CIDR,', 'IP6-CIDR,', 'GEOIP,')
    all_ip_raw = [r for r in (regular_rules + passthrough_rules) if r.startswith(ip_prefixes)]
    collapsed_ip_rules = collapse_ip_rules(all_ip_raw)

    regular_domains = [r for r in regular_rules if not r.startswith(ip_prefixes)]
    passthrough_domains = [r for r in passthrough_rules if not r.startswith(ip_prefixes)]

    # 2. 分离提取常规规则中的 HOST 与 HOST-SUFFIX
    host_rules = set()
    suffix_rules = set()
    other_rules = set()

    for r in regular_domains:
        parts = r.split(',')
        rtype, rval = parts[0], parts[1].lower()
        if rtype == 'HOST':
            host_rules.add(rval)
        elif rtype == 'HOST-SUFFIX':
            suffix_rules.add(rval)
        else:
            other_rules.add(r)

    # 激进特性 1：【安全白名单外的主域无差别向上折叠】 (Aggressive eTLD+1 Folding)
    kept_hosts = set()
    for h in host_rules:
        etld1 = get_etld1(h)
        if etld1 in PROTECTED_ETLD1:
            kept_hosts.add(h)  # 受保护大厂基础设施，保持精确单点拦截，防误杀
        else:
            suffix_rules.add(etld1) # 激进提权至后缀拦截

    # 3. 嵌套后缀无情去重 (O(1) 级联查找)
    sorted_suffixes = sorted(suffix_rules, key=len)
    suffix_set = set()
    for s in sorted_suffixes:
        s_lower = s.lower().strip('.')
        if is_domain_covered_by_suffix(s_lower, suffix_set):
            continue
        suffix_set.add(s_lower)

    # 4. 预编译特征库
    ad_pattern = re.compile('|'.join(CORE_AD_KEYWORDS), re.I)

    final_rules = set()

    for r in other_rules:
        final_rules.add(r)

    # 4.1 直通源绝对豁免权
    for r in passthrough_domains:
        parts = r.split(',')
        rtype, rval = parts[0], parts[1].lower()
        if rtype == 'HOST':
            if not is_domain_covered_by_suffix(rval, suffix_set):
                final_rules.add(r)
        elif rtype == 'HOST-SUFFIX':
            if not is_domain_covered_by_suffix(rval, suffix_set):
                final_rules.add(f"HOST-SUFFIX,{rval},{POLICY_NAME}")
                suffix_set.add(rval)
        else:
            final_rules.add(r)

    # 4.2 处理超级精炼后的 HOST-SUFFIX
    for s in suffix_set:
        if not s.endswith(ALLOWED_TLD) or len(s) > 35:
            continue

        is_hot = any(hot in s for hot in HOT_DOMAINS)
        is_mobile_core = any(net in s for net in CORE_MOBILE_AD_NETWORKS)
        is_ad_kw = bool(ad_pattern.search(s))

        rule_str = f"HOST-SUFFIX,{s},{POLICY_NAME}"
        
        if is_mac:
            # Mac 端：长尾广告保留，但依赖激进折叠已大幅缩减体积
            if is_hot or is_mobile_core or is_ad_kw:
                final_rules.add(rule_str)
        else:
            # 激进特性 2：【Mobile 极简模式】
            if is_mobile_core or is_hot or (is_ad_kw and len(s) <= 16):
                final_rules.add(rule_str)

    # 4.3 处理幸存的高敏单点 HOST (仅限于 PROTECTED_ETLD1 内部的子域)
    for rval in kept_hosts:
        if is_domain_covered_by_suffix(rval, suffix_set):
            continue
        if not rval.endswith(ALLOWED_TLD) or len(rval) > 35:
            continue

        is_hot = any(hot in rval for hot in HOT_DOMAINS)
        is_mobile_core = any(net in rval for net in CORE_MOBILE_AD_NETWORKS)
        is_ad_kw = bool(ad_pattern.search(rval))

        rule_str = f"HOST,{rval},{POLICY_NAME}"
        if is_mac:
            if is_hot or is_mobile_core or is_ad_kw:
                final_rules.add(rule_str)
        else:
            if is_mobile_core or is_hot:
                final_rules.add(rule_str)

    # 4.4 加入合并后的 IP-CIDR 规则
    final_rules.update(collapsed_ip_rules)

    # 5. 按优先级与字典序排序
    def sort_key(rule):
        rtype = rule.split(',')[0]
        priority = RULE_PRIORITY.get(rtype, 99)
        return (priority, rule.lower())

    return sorted(list(final_rules), key=sort_key)


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


def generate_clash_yaml(name, rules, source_counts=None):
    counts = {t: 0 for t in RULE_PRIORITY.keys()}
    for r in rules:
        rtype = r.split(',')[0]
        if rtype in counts:
            counts[rtype] += 1

    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    yaml_lines = [
        f'# NAME: {name}',
        f'# UPDATED: {now}',
        f'# DOMAIN: {counts.get("HOST", 0)}',
        f'# DOMAIN-SUFFIX: {counts.get("HOST-SUFFIX", 0)}',
        f'# DOMAIN-KEYWORD: {counts.get("HOST-KEYWORD", 0)}',
        f'# IP-CIDR: {counts.get("IP-CIDR", 0) + counts.get("IP6-CIDR", 0)}',
        f'# TOTAL: {len(rules)}'
    ]

    if source_counts:
        for s_key in SOURCES.keys():
            count = source_counts.get(s_key, 0)
            yaml_lines.append(f'# RETAINED-{s_key.upper()}: {count}')

    yaml_lines.append('payload:')

    clash_rules = []
    for r in rules:
        parts = r.split(',')
        rtype = parts[0]
        rval = parts[1]
        clash_type = QX_TO_CLASH.get(rtype)
        if not clash_type:
            continue

        rule_str = f'{clash_type},{rval}'
        if 'IP' in clash_type or 'IP-CIDR' in rtype or 'no-resolve' in r.lower():
            if 'no-resolve' not in rule_str.lower():
                rule_str += ',no-resolve'

        clash_rules.append(f'  - {rule_str}')

    return '\n'.join(yaml_lines + clash_rules) + '\n'


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
        # 检查是否满 4 天 (强制刷新一次)
        if self.data.get("consecutive_unchanged_days", 0) >= 4:
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
        print(f"Error: Output directory {output_dir} is outside of current workspace.", file=sys.stderr)
        sys.exit(1)
    os.makedirs(output_dir, exist_ok=True)

    cache = RuleCache(os.path.join(os.getcwd(), CACHE_FILE))

    print(f"Fetching raw data (Parallel)... {'[FORCE MODE]' if args.force else ''}", flush=True)
    source_rules = {}
    source_totals = {}

    def fetch_task(name_url):
        name, url = name_url
        return name, fetch_rules(url)

    with ThreadPoolExecutor(max_workers=len(SOURCES)) as executor:
        results = list(executor.map(fetch_task, SOURCES.items()))

    all_raw = []
    passthrough_raw = []
    regular_raw = []
    for name, (data, total) in results:
        if data is None:
            print(f"CRITICAL: Failed to fetch {name}. Aborting.", file=sys.stderr)
            sys.exit(1)
        source_rules[name] = set(data)
        source_totals[name] = total
        all_raw.extend(data)
        if name in PASSTHROUGH_SOURCES:
            passthrough_raw.extend(data)
        else:
            regular_raw.extend(data)

    # 缓存检查判定逻辑
    is_forced = args.force or cache.data.get("consecutive_unchanged_days", 0) >= 4

    # 只有在非强制模式且 cache 建议跳过时才跳过
    if not is_forced and cache.should_skip(source_totals):
        print(f"Skipping: All sources unchanged and within 4 days ({cache.data.get('consecutive_unchanged_days')} days).", flush=True)
        cache.update(source_totals, is_changed=False)
        return

    if not all_raw:
        sys.exit(1)

    print("Optimizing and Sorting...", flush=True)
    if is_forced:
        print(f"Update triggered: {'Force mode' if args.force else '4 days limit reached'}.", flush=True)

    optimized_mobile = smart_optimize(regular_raw, passthrough_raw, is_mac=False)
    optimized_mac = smart_optimize(regular_raw, passthrough_raw, is_mac=True)

    # Clash 采用合集 (去重)
    unified_rules = sorted(
        list(set(optimized_mobile + optimized_mac)),
        key=lambda r: (RULE_PRIORITY.get(r.split(',')[0], 99), r.lower())
    )

    outputs = [
        ("Mobile_Unified.list", optimized_mobile, "qx"),
        ("Mac_Unified.list", optimized_mac, "qx"),
        ("Clash_Unified.yaml", unified_rules, "clash")
    ]

    for filename, rules, fmt in outputs:
        filepath = os.path.join(output_dir, filename)

        source_counts = {}
        for s_name, s_set in source_rules.items():
            source_counts[s_name] = sum(1 for r in rules if r in s_set)

        fd, temp_path = tempfile.mkstemp(dir=output_dir, text=True)
        try:
            with os.fdopen(fd, 'w') as tf:
                if fmt == "qx":
                    tf.write(generate_header(filename.split('.')[0], rules, source_counts))
                    tf.write("\n".join(rules))
                else:
                    tf.write(generate_clash_yaml(filename.split('.')[0], rules, source_counts))

            shutil.move(temp_path, filepath)
            print(f"Saved {filename}: {len(rules)} rules", flush=True)
        except Exception as e:
            print(f"Error saving {filename}: {e}", file=sys.stderr)
            if os.path.exists(temp_path):
                os.remove(temp_path)
            sys.exit(1)

    # 强制更新或有变化时，重置计数器
    cache.update(source_totals, is_changed=True)
    print("Success!", flush=True)


if __name__ == "__main__":
    main()
