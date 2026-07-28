# ScopeGraph v1.0 兼容性矩阵

| 环境 | 状态 | 验证范围 |
|---|---|---|
| Windows 11 10.0.26200 + Docker Desktop 28.0.1 | 已实测 | Compose 构建、迁移、全服务、Phase 2–7 E2E、容量、Worker 重启 |
| Linux/amd64 容器（Python 3.12-slim、Node 22-alpine） | 已实测 | API、Worker、Web production image、10/10 工具链、Chromium 中文渲染和 PostgreSQL/Redis 集成 |
| WSL2 独立 Ubuntu 发行版 | 容器级支持，未在本机独立实测 | 本机只有 `docker-desktop` WSL2 发行版 |
| Kali Rolling（2026-07-17 镜像，Python 3.13.14） | 已实测（CLI/用户态） | 源码构建安装、`doctor`、Deep 二次确认门、Nmap 7.99 路径检测 |
| macOS / ARM64 | 未声明支持 | v1.0 未执行实机验证 |

## 运行时基线

- Python 3.12–3.13（本机验证 3.12.13；Kali 容器验证 3.13.14）；
- Node.js 20.9+，镜像使用 Node 22；
- PostgreSQL 17、Redis 7；
- Docker Compose v2。

ScopeGraph 不按未经验证的版本号盲目放行外部工具，而是执行各适配器的版本命令并检查工具
签名。系统页显示安装路径、原始版本输出、最低版本提示和兼容结论；不兼容任务返回
`TOOL_INCOMPATIBLE`。版本更新必须由用户确认并手工完成。

Kali 实测使用临时 `kalilinux/kali-rolling` 用户态容器连接 ScopeGraph Compose 网络；
ScopeGraph 1.0.0 成功构建安装，`scopegraph doctor` 对 API、数据库、Redis、存储均返回健康，
Nmap 7.99 被适配器识别为 `/usr/bin/nmap`。源码/Python 包安装仍不捆绑外部工具；正式推荐的
Docker 镜像则已经内置完整工具链，并在 Windows Docker Desktop 环境验证为 10/10 兼容。
