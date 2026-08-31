# test-a — 广告/隐私规则集统一处理器

## 项目概述

Python 规则处理项目。从受信任上游拉取 QX / Surge / Clash 风格规则，经安全规范化、PSL 校验、结构随机域名筛选、规则血缘记录和按使用场景选择后，输出 Clash/mihomo 与 Quantumult X 规则。

## 技术栈

- Python 3.10+
- 固定依赖：`requests`、`tldextract`
- 测试：标准库 `unittest`
- 自动化：GitHub Actions

## 输出文件

```text
dist/
├── Clash_Unified.yaml  # 完整 Clash/mihomo 规则集；目标 12k，最大 20k
├── QX_Universal.list   # 桌面/通用 QX；目标 10k，最大 20k
├── QX_Compact.list     # 移动 QX；目标 2k，最大 5k
├── Rule_Report.md
├── rule_decisions.jsonl
├── rule_baseline.json
└── manifest.json
```

`QX_Universal` 与 `QX_Compact` 不要求互相包含，但两者必须是 `Clash_Unified` 的子集。旧的 `Mac_Unified.list`、`Mobile_Unified.list`、`Mobile_Lite.list`、`Clash_Lite.yaml` 不再生成。

## 常用命令

```bash
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v

# 构建候选到 preview-dist/，不改动 dist/
python scripts/process_rules.py --preview-only --force
```

## 安全与处理原则

1. 上游下载使用 TLS 校验、受限 HTTPS 主机、最多三次重定向、响应大小上限与有限重试；任一来源失败则不发布。
2. 域名先做 IDNA/Punycode 规范化，再用固定离线 PSL（ICANN + Private Domains）校验；拒绝 public/private suffix 根。
3. 不会将上游 `HOST` 自动扩大成 `HOST-SUFFIX`；仅当同一输出中已选中原生 suffix 时才可覆盖子规则。
4. 删除长纯数字、长十六进制与高数字比例的结构随机域名；BlockDNS、显式 catalog 和完全双源共识是受控例外。
5. 广告/追踪分类只匹配完整 DNS label，不能用任意子串推断。例如 `ads.example.com` 可匹配 `ads`，`myads.example.com`、`adobe.example.com` 不会匹配。
6. BlockDNS 原生 HOST/HOST-SUFFIX/CIDR 在三个输出中完整保留，不被普通 suffix 覆盖去重删除。

## 策略配置

- `scripts/sources.json`：来源 URL、角色、允许主机、下载上限、共识资格。
- `scripts/rule_policy.json`：输出 target/max、结构随机阈值、完整 label 分类与 evidence catalog。

Catalog 使用平台标签：

```json
{
  "platforms": ["web", "mobile", "shared"],
  "lite_enabled": true
}
```

- `web`：Clash 与 QX Universal；
- `mobile`：Clash 与 QX Compact；
- `shared`：三个输出；
- Compact 还要求 `lite_enabled: true`。

修改 policy 或 sources 配置时必须递增对应版本号，并走 Preview → 审阅 → initialize baseline 的发布流程。
