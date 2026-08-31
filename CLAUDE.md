# test-a — 广告/隐私规则集统一处理器

## 项目概述

Python 规则处理项目。它从多个受信任的上游规则源拉取 Quantumult X / Surge / Clash 风格规则，经过安全规范化、PSL 校验、来源血缘记录和分层选择，生成供 Quantumult X、Clash、mihomo 使用的 Stable 与 Lite 规则集。

## 技术栈

- Python 3.10+
- 依赖：`requests`、`tldextract`（固定于 `requirements.txt`）
- 测试：标准库 `unittest`
- 自动化：GitHub Actions

## 目录结构

```text
test-a/
├── scripts/
│   ├── process_rules.py       # CLI 入口及处理器版本
│   ├── rule_policy.json       # 分层准入、关键词、护栏策略
│   ├── sources.json           # 上游来源与下载信任边界
│   └── rules/                 # 解析、规范化、下载、选择、报告、护栏模块
├── dist/                      # 完全由处理器管理的发布产物
├── tests/                     # 离线 unittest 测试与 fixtures
├── requirements.txt
└── .github/workflows/
    ├── ci.yml                 # 离线 CI
    └── update.yml             # Preview 与受控发布
```

## 常用命令

```bash
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v

# 生成候选到 preview-dist/，不覆盖 dist/
python scripts/process_rules.py --preview-only --force

# 常规生成；仅在已有受管 baseline 时替换 dist/
python scripts/process_rules.py
```

## 安全与规则处理原则

1. 所有上游下载都使用 TLS 校验；仅允许来源配置中的 HTTPS 主机、最大三跳重定向和受限响应体积。任一启用来源失败即不发布。
2. 输入类型统一到内部规则模型，并保留每条规则的来源、行号、原始文本和处理决定。
3. 域名先 IDNA/Punycode 规范化，再用固定、离线 `tldextract` PSL（ICANN + Private Domains）校验。
4. **绝不**将 `HOST` 自动提升为 `HOST-SUFFIX`。只有最终保留的原生 `HOST-SUFFIX` 才能覆盖其子规则。
5. 值等于 PSL public/private suffix 根的域名型规则会被拒绝，例如 `blogspot.com`、`github.io`。
6. Stable 保留结构安全、格式有效的原生规则；Mobile Stable 只移除不在 allowlist 的 `HOST-KEYWORD`；Lite 只收录高置信度 SDK/端点、DNS 绕过直通规则或两常规来源完全一致的规则。
7. IP/CIDR 不合并相邻网段；仅做保守重复/包含去重，并保留 `no-resolve` 语义。
8. Clash 不支持 `USER-AGENT`：渲染时排除并在文件头和报告中如实统计。

## 修改来源与策略

- 修改 URL、角色、跳转主机或下载上限：编辑 `scripts/sources.json` 并递增 `sources_version`。
- 修改 Lite allowlist、关键词规则、GEOIP 或发布护栏：编辑 `scripts/rule_policy.json` 并递增 `policy_version`。
- 每个 Lite allowlist 条目须包含稳定 ID、`exact`/`suffix` 匹配方式、类别、说明和证据。
- 策略/来源/处理器版本变动必须走 GitHub Actions 的 Preview → 审阅 artifact → `initialize_baseline` 流程，不能由定时任务自动接受。

## 发布产物与审计

`dist/` 包含规则文件、`Rule_Report.md`、完整 `rule_decisions.jsonl`、`rule_baseline.json` 和 `manifest.json`。不要手动编辑或放置额外文件；`manifest.json` 定义受管输出，发布时会阻止删除未知文件。

旧的 `scripts/rule_cache.json` 为遗留文件，处理器不再读取或更新它。构建身份由来源 canonical hash、策略/来源配置、依赖身份和处理器版本共同决定；只有全部不变时才跳过重建。
