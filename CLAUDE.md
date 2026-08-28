# test-a — 广告/隐私规则集统一处理器

## 项目概述
Python 脚本项目。从多个上游规则源（blackmatrix7 等）拉取 QuantumultX 格式的广告/隐私规则，经过去重、优先级排序、格式转换后，生成统一的多格式规则文件，供 QuantumultX、Clash、mihomo 等代理工具使用。

## 技术栈
- Python 3（无虚拟环境框架，依赖标准库 + 少量第三方库）
- 主要依赖：`requests`（HTTP 下载）
- 自动化：GitHub Actions

## 目录结构
```
test-a/
├── scripts/
│   ├── process_rules.py    # 核心处理脚本（规则拉取、去重、转换、输出）
│   └── rule_cache.json     # 规则缓存文件（避免重复下载）
├── dist/                   # 输出目录（自动生成，勿手动编辑）
│   ├── Clash_Unified.yaml  # Clash/mihomo 格式（rule-provider）
│   ├── Mac_Unified.list    # QuantumultX macOS 格式
│   └── Mobile_Unified.list # QuantumultX 移动端格式
├── .github/
│   └── workflows/          # GitHub Actions 工作流
└── README.md
```

## 常用命令
```bash
# 运行规则处理（输出到 dist/）
python scripts/process_rules.py

# 安装依赖
pip install requests
```

## 规则处理逻辑
1. 从 `SOURCES` 配置的 URL 并发拉取规则（`requests` 流式下载）
2. 过滤注释行，按优先级排序（HOST > HOST-SUFFIX > HOST-KEYWORD > IP > USER-AGENT）
3. 去重、过滤低质量规则（非主流 TLD、非广告关键词的泛域名）
4. 保留核心热门域名白名单（`HOT_DOMAINS`）
5. QX 格式 → Clash 格式转换（HOST → DOMAIN 等）
6. 输出三种格式到 `dist/`

## 修改上游规则源
在 `scripts/process_rules.py` 顶部的 `SOURCES` 字典中添加/修改 URL：
```python
SOURCES = {
    "privacy": "https://...",
    "adlite":  "https://..."
}
```

## 注意事项
- `dist/` 目录内容由 GitHub Actions 自动更新，本地运行也会覆盖
- `USER-AGENT` 规则在 Clash 格式中会被自动跳过（不支持）
- 规则缓存在 `scripts/rule_cache.json`，可删除强制重新下载
