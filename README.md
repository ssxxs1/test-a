# test-a

安全、可审计的广告与隐私规则处理器。它将多个上游规则规范化、执行 PSL 与结构安全校验，并输出 Clash/mihomo、通用 QX 与移动 QX 规则。

## 订阅产物

| 文件 | 场景 | 目标 / 硬上限 |
| --- | --- | --- |
| `dist/Clash_Unified.yaml` | 完整 Clash/mihomo 规则集 | ~12,000 / 20,000 |
| `dist/QX_Universal.list` | 桌面与通用 Quantumult X | ~10,000 / 20,000 |
| `dist/QX_Compact.list` | 移动 Quantumult X | ~2,000 / 5,000 |

`QX_Universal` 与 `QX_Compact` 按访问场景独立选择，不要求互相包含；两者都必须是 `Clash_Unified` 的子集。

旧的 `Mac_Unified.list`、`Mobile_Unified.list`、`Mobile_Lite.list`、`Clash_Lite.yaml` 将不再生成，订阅地址需要迁移。

## 安全模型

- 不会将精确 `HOST` 自动扩大为 `HOST-SUFFIX`。
- 使用固定、离线 PSL（ICANN + Private Domains）；拒绝 `blogspot.com` 这类公共/私有后缀根规则。
- 对长纯数字、长十六进制和高数字比例 label 执行结构随机域名拒绝；BlockDNS、明确证据 catalog 和严格双源共识例外保留。
- 规则分类只匹配完整 DNS label，绝不因 `myads`、`adobe`、`trackingservice` 等子串推断广告属性。
- BlockDNS 是三档的完整原生 passthrough，保留其 HOST/CIDR 粒度并不受普通 suffix 去重影响。

## 本地使用

```bash
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
python scripts/process_rules.py --preview-only --force
```

Preview 写入 `preview-dist/`，不会覆盖生产 `dist/`。策略、来源或处理器版本变更后必须通过 GitHub Actions Preview 审阅，再使用该 Preview Run ID 初始化新 baseline。

## 策略配置

- `scripts/sources.json`：上游 URL、TLS/重定向允许主机、角色、体积上限和共识资格。
- `scripts/rule_policy.json`：三档 target/max、结构随机阈值、完整 label 分类和 evidence catalog。

Catalog 条目使用：

```json
{
  "platforms": ["web", "mobile", "shared"],
  "lite_enabled": true
}
```

`web` 进入 Clash 与 Universal，`mobile` 进入 Clash 与 Compact，`shared` 进入三档；Compact 还要求 `lite_enabled`。
