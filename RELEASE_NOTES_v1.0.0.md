# ScopeGraph v1.0.0 发布说明

ScopeGraph v1.0.0 是按项目开发书阶段 0–7 完成的首个可交付版本。推荐以 Docker Compose 在
单机、回环网络环境运行。核心闭环为：企业名/已知根域 → 候选与人工 Scope → 受控扫描 DAG →
资产/网站/备案/发现 → 人工审核 → 历史差异 → 五种格式导出。

## 发布质量

- 128 项 Python 测试、16 项 Web 测试；全仓 Ruff/mypy/ESLint/TypeScript 通过；
- Phase 2–7 与 MCP SDK 启动/轮询 E2E 全部通过，六个常驻 Docker 服务健康；
- 指定中型容量全部完成：10k 候选、1k DNS/HTTP、500 截图计划、100k Observation；
- Worker 停机期间排队的任务在重启后恢复；
- XLSX 11 个工作表已独立导入、公式检查和渲染 QA。

## 重要安全默认值

- 仅扫描明确 Scope，第三方 CNAME/CDN/私网不扩展；
- host 模式、全端口和 Nuclei 均需要额外确认；
- Nuclei 只运行固定低风险标签，输出不是已确认漏洞；
- 外部命令全部使用参数数组；代理拒绝凭据与附加路径；
- 端口只绑定 `127.0.0.1`，非回环模式强制 API Key；
- 工具不静默升级，版本签名不兼容即阻止。

## 已知边界

- AMD64 Docker 镜像已捆绑并固定 10 个扫描/浏览工具及 Nuclei 模板；其他架构仍需单独验证；
- Kali Rolling 已实测 Python 包构建、CLI/`doctor`、Deep 安全门和 Nmap 7.99 检测；独立
  WSL2 Ubuntu、完整 ProjectDiscovery/系统 Chrome 原生链路、macOS/ARM64 尚未实测，不能
  视为已认证平台；
- 浏览器视觉自动化尚未纳入 CI；已完成 Docker production build、真实 UI 路由 HTTP 验收和
  本地浏览器视口复核，但每次重大布局调整仍应重复视觉验收；
- v1 只覆盖公开攻击面，不发现内网资产，也不替代人工归属与漏洞复核。

部署前请阅读 `docs/INSTALLATION.md`、`docs/COMPATIBILITY.md` 和备份文档。
