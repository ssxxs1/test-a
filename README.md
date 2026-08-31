# test-a

安全、可审计的广告与隐私规则处理器。它从受信任的上游拉取规则，保留原始匹配粒度，生成 Stable 与 Lite 两类 Quantumult X、Clash/mihomo 规则集。

## 输出

| 文件 | 说明 |
| --- | --- |
| `dist/Mac_Unified.list` | 完整 Stable Quantumult X 规则集 |
| `dist/Mobile_Unified.list` | 轻量 Stable Quantumult X 规则集 |
| `dist/Clash_Unified.yaml` | 完整 Stable Clash/mihomo provider |
| `dist/Mobile_Lite.list` | 高置信度 Lite Quantumult X 规则集 |
| `dist/Clash_Lite.yaml` | 高置信度 Lite Clash/mihomo provider |
| `dist/Rule_Report.md` | 可读构建与安全决策摘要 |
| `dist/rule_decisions.jsonl` | 每条来源规则的完整决策血缘 |
| `dist/rule_baseline.json` | 已批准输出的发布护栏基线 |
| `dist/manifest.json` | 受管输出、hash 和构建身份清单 |

## 安全模型

- 不会将精确 `HOST` 自动扩大为 `HOST-SUFFIX`。
- 采用固定版本、离线 PSL 的 `tldextract`，并识别 ICANN 与 Private Domains；例如拒绝 `HOST-SUFFIX,blogspot.com`，但可保留具体租户规则。
- Stable 保留通过格式和 PSL 安全校验的原生上游规则；Mobile Stable 只收紧泛化关键词；Lite 仅收录 SDK/联盟、人工审核端点、DNS 绕过直通项或两个常规来源完全一致的规则。
- 所有规则都有来源血缘、规范化状态、策略决策和覆盖关系记录在 JSONL 审计文件中。
- 上游下载启用 TLS 校验，逐跳限制 HTTPS/允许主机、最大 3 次重定向、输入大小上限和有限重试；任一来源失败即不发布。

## 本地使用

```bash
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v

# 只生成可审阅候选，不替换 dist/
python scripts/process_rules.py --preview-only --force

# 常规生产生成（仅在已有受管基线时发布）
python scripts/process_rules.py
```

候选文件写入 `preview-dist/`。首次发布必须经过 GitHub Actions Preview 审阅并使用 `initialize_baseline` 建立受控基线；不要把旧的激进输出直接当作新基线。

## 配置

- `scripts/sources.json`：来源 URL、角色、允许跳转主机、上限和共识资格。
- `scripts/rule_policy.json`：QX 策略名、Lite allowlist、关键词策略、GEOIP 策略和发布护栏。

两份配置都有版本号和内容 hash。策略、来源配置或处理器语义变动必须先 Preview、审阅并建立新基线。

## CI 与发布

- `.github/workflows/ci.yml`：push/PR 离线单元测试，不访问上游、不发布文件。
- `.github/workflows/update.yml`：定时/手动构建。Preview 上传 14 天 artifact；发布前执行来源、解析率、规则总量和新增根后缀护栏。
- 手动异常发布必须提供 `approve_anomalous_publish`、`approval_reason` 和已审阅的 `preview_run_id`。
