# ScopeGraph v1.0 安装

## 推荐安装：Docker Desktop / Docker Engine

要求：Docker 24+、Compose v2、至少 4 CPU、8 GiB 内存和 20 GiB 可用空间。Windows 建议
Docker Desktop + WSL2 后端。

```powershell
Copy-Item .env.example .env
docker compose config --quiet
docker compose up -d --build
docker compose ps
docker compose exec api scopegraph doctor --json
```

所有服务健康后访问 <http://127.0.0.1:18080>。Community Edition 默认使用独立的
`scopegraph-community` Compose 项目、`scopegraph-community-api` 镜像名和 180xx 宿主机端口，
不会复用同一目录旁内部版的容器与数据卷。数据库与 Redis 不发布宿主机端口，Web/API 仅发布到
回环地址。首次启动自动执行 Alembic 迁移。

## 安全配置

日常使用保持默认回环绑定。若确实需要修改 Compose 端口为非回环地址：

1. 在 `.env` 设置 `SCOPEGRAPH_PUBLIC_BIND=true`；
2. 生成至少 32 字节随机 `SCOPEGRAPH_API_KEY`；
3. 确认反向代理启用 TLS、来源限制和访问日志；
4. API 客户端发送 `X-ScopeGraph-API-Key`。Web 容器会从服务端环境变量转发该密钥，不会把
   密钥下发给浏览器 JavaScript。

API 在公开模式缺少密钥时会拒绝启动。不要把 `.env` 提交到版本库。代理/Burp 地址在系统页
设置，只接受无凭据的 `http://host:port` 或 `https://host:port`。

## 工具模式

Docker 镜像已经内置并固定 Subfinder、PureDNS、MassDNS、AlterX、dnsx、Naabu、Nmap、
httpx、Chromium、Katana 和 Nuclei。ProjectDiscovery 发布包在构建时使用官方 checksum
校验；Nuclei 同时内置固定版本的官方模板，避免首次扫描因缺少模板直接失败。系统页运行时逐项
检测 10 个适配器，正常安装应显示 `10/10` 兼容。Chromium 镜像同时包含 Noto CJK 字体，
中文页面截图可正常渲染。

Python 的直接依赖与影响运行边界的关键传递依赖由 `constraints/python312.txt` 约束到当前已验收
的 Python 3.12 版本，Docker 和 CI 均使用这份约束。它不是跨平台 wheel 的完整哈希锁文件；升级
依赖时必须同时重跑源码、Compose、fixture E2E 和 MCP 验收。

Docker 默认使用 Debian 官方软件源。如果所在网络需要区域镜像，可在 `.env` 显式设置
`SCOPEGRAPH_DEBIAN_MIRROR` 与 `SCOPEGRAPH_DEBIAN_SECURITY_MIRROR`。例如中国大陆环境可选择
`.env.example` 中注释的 USTC 地址。镜像选择不会在程序运行或扫描期间自动改变。

Windows 启动脚本默认执行增量构建并等待 Web 健康；`Start-ScopeGraph.cmd --no-open` 适合
终端/自动化验收，`--no-build` 仅在确认现有镜像与源码一致时使用。`--check` 只做 Docker、Compose
和引擎预检，不启动服务；`--offline-check` 只解析本地 Compose 配置，不联系 Docker、浏览器或扫描
目标。失败时脚本会输出服务状态与最近日志，而不是只停留在笼统错误提示。

Web 默认选择“真实扫描（Docker 内置工具）”；只有明确选择“演示数据（离线 fixture）”时才
使用录制数据。真实扫描只应针对已授权并已加入 Scope 的根域，仍需在任务表单中再次确认授权。
工具缺失或版本签名不兼容会安全阻止对应任务；ScopeGraph 不在运行期间静默升级工具。
