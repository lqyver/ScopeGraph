# 阶段 7 / v1.0 发布记录

> 本文记录阶段 7 完成时的历史测量，不代表当前工作树已经重新完成 Docker 发布验收。当前
> Community Edition 发布状态以 `PUBLIC_RELEASE_READINESS.md` 为准。

## 完成内容

- 10 个工具适配器的安装路径、版本输出和兼容签名检查；不执行静默更新，更新请求必须确认，
  然后提示用户手工更新和复检；
- httpx、Katana、Screenshot、Nuclei 的 HTTP(S) 代理/Burp 转发；代理经闭合字段校验，拒绝
  凭据、路径、查询参数和片段；
- Docker 端口默认只发布到 `127.0.0.1`；显式非回环模式没有 API Key 时 API 拒绝启动，比较
  使用恒定时间函数；Web 服务端代理安全转发密钥；
- `/system` 系统页：工具兼容、存储、监听保护和默认代理；
- CLI 补齐企业发现、候选根域、审核、扫描差异、导出、Nuclei 二次确认和代理；
- Deep 完全扫描在 API、CLI、Web 三层二次确认；Custom Profile 在 CLI/Web 接受最多 64 KiB
  的闭合 JSON 配置，未知字段、任意命令和越界参数由后端拒绝；
- 安装、升级、备份/恢复、兼容性和 v1.0 发布说明。

## 自动与实机验收

- Python 89 项单元测试；Web 10 项 Vitest；Ruff、mypy strict、ESLint、TypeScript 全通过；
- Docker production build 成功，Alembic 为 `0008_phase_six (head)`，API、Worker、Web、
  PostgreSQL、Redis 全部健康；
- Phase 2–7 六组 E2E 全通过，Phase 7 另验证系统工具、更新确认、代理校验/扫描、清理确认和
  3 个 UI 路由；Deep 缺少确认返回 422，合法 Deep 完成，Custom 任意命令被拒绝且合法闭合
  配置扫描成功；
- 最终 API 镜像公开模式实测：缺失 Key 401、错误 Key 401、正确 Key 200；容器 CLI 和健康检查
  能从服务端环境安全携带 Key；
- Worker 停止时提交任务，重启后从 Redis 持久队列恢复并完成为 `PARTIAL_SUCCESS`；
- Kali Rolling 用户态实测通过：Python 3.13.14 构建安装 ScopeGraph 1.0.0，CLI `doctor`
  返回 API/数据库/Redis/存储全健康，Nmap 7.99 被识别为 `/usr/bin/nmap`，缺少
  `--confirm-deep` 的 Deep 请求在访问 API 前被 CLI 拒绝；
- 最终镜像容量实测：10,000 候选域名插入 12.995 秒，重复写入去重 12.393 秒；1,000 DNS
  解析 0.347 秒，1,000 HTTP 解析 0.932 秒；500 截图计划 0.098 秒；100,000 Observation
  插入 16.123 秒、查询归并 11.189 秒；Python 峰值 252.8 MiB。

## 平台结论

Windows 11 + Docker Desktop 28.0.1 + Compose 2.33.1 的 Linux/amd64 容器链路已实测；
Kali Rolling 的 Python 包、CLI 和 Nmap 适配器检测也已在隔离用户态容器中实测。本机没有
独立 WSL2 Ubuntu/Kali 发行版，因此未把 WSL2 shell、系统 Chrome 或完整 ProjectDiscovery
原生工具链冒充实测；兼容性矩阵明确区分验证边界。
