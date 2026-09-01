# ScopeGraph Community Edition 发布候选说明

这是按项目开发书阶段 0–7 完成的 Community Edition 发布候选。它不是已打正式 tag 的 v1.0.0
发行版；推荐以 Docker Compose 在
单机、回环网络环境运行。核心闭环为：企业名/已知根域 → 候选与人工 Scope → 受控扫描 DAG →
资产/网站/备案/发现 → 人工审核 → 历史差异 → 五种格式导出。

## 发布质量

- 147 项 Python 测试、20 项 Web 测试；全仓 Ruff/mypy/ESLint/TypeScript 通过；
- Phase 2–7 与 MCP SDK 启动/轮询 E2E 全部通过，六个常驻 Docker 服务健康；
- 指定中型容量全部完成：10k 候选、1k DNS/HTTP、500 截图计划、100k Observation；
- Worker 停机期间排队的任务在重启后恢复；
- XLSX 11 个工作表已独立导入、公式检查和渲染 QA。

## 运行可靠性维护

- Windows 启动脚本现在拒绝未知参数，并为 Docker 探测、API/Web 健康请求设置有界超时；
- `--check` 只做 Docker/Compose/引擎预检，`--offline-check` 只解析本地配置，不启动服务、浏览器或扫描目标；
- 启动失败会区分预检失败与运行期服务失败，避免 Docker 不可用时继续等待或拉取无关日志。
- Community Edition 默认使用 `scopegraph-community` Compose 项目、独立镜像名和 180xx 宿主机端口，
  避免与旁边的 Internal Edition 复用容器、镜像或数据卷；启动脚本会打印当前版本和实际 Web 端口。
- 公开源码包只允许从本仓库的干净提交通过 `git archive` 生成；内部版 `dist/` 产物不是公开发布输入。
- Docker 与 CI 使用 `constraints/python312.txt` 固定已验收的 Python 3.12 直接依赖与关键传递依赖；CI 的
  Compose 门覆盖 Phase 2–7、异步企业发现、MCP 默认安全门和 Worker 重启恢复。
- Debian 构建源默认为官方端点，也允许管理员通过显式环境变量选择区域镜像。
- 演示扫描完成后的资产和网站链接会保留 fixture 证据筛选，避免结果实际存在但页面默认显示为空；
  网站视图控制在 390px 移动端改为纵向布局，不再造成整页横向滚动。

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
