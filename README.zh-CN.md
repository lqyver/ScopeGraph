# ScopeGraph

ScopeGraph 是面向合法授权安全测试的本地企业公网攻击面发现平台。本仓库严格按照
[`ScopeGraph_PRD_Development_Guide_v1.0.md`](./ScopeGraph_PRD_Development_Guide_v1.0.md)
分阶段实现。

> **社区版本。** 本仓库采用 Apache-2.0，默认使用独立 Compose 项目 `scopegraph-community`
> 以及宿主机端口 `18000`/`18001`/`18080`，不会复用内部版的容器、镜像或数据卷。

当前版本为 **Community Edition Release Candidate**，已完成开发书阶段 0–7。系统提供企业名称候选根域发现、可解释归属
评分、人工 Scope 审核、四类扫描 Profile、DNS/IP/端口/Web/备案资产图谱、Nuclei 低风险发现、
任意扫描历史差异、五种导出格式、存储管理、工具兼容检查、代理/Burp 转发、Web 与 CLI。
Standard/Deep Profile 使用受控并行 DAG：Subfinder 后 PureDNS 与 AlterX 并行，DNS 汇总后
端口分支与 HTTP 分支并行，HTTP 完成后截图、Katana 与 Nuclei（已授权时）并行。默认
Web 流程使用 Docker 内置真实工具；`fixture` 仅作为显式选择的离线演示模式。真实扫描必须再次
确认授权和主动执行。Deep Profile 必须二次确认；
Custom Profile 只接受闭合 JSON 策略，未知字段和任意命令会被拒绝。

企业发现默认保持被动：公开搜索、候选根域的证书 SAN 佐证，以及公开 RDAP
注册人精确匹配均独立记录来源、请求完成度和失败原因。来源失败、正常完成但无命中、以及获得多源
交叉支持的候选会在页面中明确区分；所有候选仍必须由人工加入 Scope，证据评分不等于授权。
运行会先持久化并在页面上按来源实时更新状态、请求完成度和错误诊断，不需要等待全部来源结束。

主动边界保持保守：CDN/WAF、私网/保留地址默认禁止端口扫描；全端口还要求 IP 明确处于
Scope、人工标记为 OWNED 并二次确认。httpx 只跟随同主机跳转并拒绝私网网段；Katana 固定
为 FQDN Scope，不启用自动填表、Cookie 或业务 POST；外部新根域只进入 `PENDING_REVIEW`。
Nuclei 默认先识别站点技术栈，再只加载与命中技术相关的低风险模板，避免“全部站点 × 全部
模板”的无界组合；Custom Profile 仍可显式选择宽模板策略。系统阻止 intrusive、fuzz、DoS、
RCE 等标签以及 code/file/headless/javascript/whois 协议；命中永远先标记为 `UNVERIFIED`。镜像内置固定
版本模板，工具不会在运行时静默升级，版本签名不兼容会安全阻止执行。

ScopeGraph 的 All-in-One 价值不是替代 Subfinder 的五秒被动枚举，而是把原始域名自动变成可行动
攻击面：统一去重和 Scope → PureDNS/DNSx 验证 → 授权域名派生 IP 的安全端口扫描 → Nmap 服务
指纹 → httpx 存活与技术栈 → Katana 网页/接口 → 技术感知 Nuclei → 历史差异与导出。独立分支
通过 DAG 并行执行；每次任务保存资产漏斗、阶段总耗时、墙钟耗时和并行节省时间。端口页面分别
显示“每 IP 测试端口/候选检查数”和“实际开放端口”，不会再把一个开放端口误写成只扫描一个。

## 当前服务

| 服务 | 技术 | 本地地址/作用 |
|---|---|---|
| Web | Next.js + TypeScript | <http://127.0.0.1:18080> |
| API | FastAPI | <http://127.0.0.1:18000> |
| API 文档 | OpenAPI | <http://127.0.0.1:18000/docs> |
| Worker | Dramatiq | Redis 队列消费者 |
| MCP | 官方 Python SDK / Streamable HTTP | <http://127.0.0.1:18001/mcp>，供本地 Agent 接入 |
| Database | PostgreSQL | 仅 Compose 内部网络 |
| Queue | Redis | 仅 Compose 内部网络 |

Web、API 与 MCP 端口均只绑定回环地址。PostgreSQL 和 Redis 不暴露宿主机端口。

## 外部 Agent / MCP

ScopeGraph 内置 MCP Server，支持 `stdio` 和 Streamable HTTP。默认只读，外部 Agent 可以查询
项目、已确认 Scope、资产、网站、网络结果、发现项和逐阶段扫描状态。管理员显式设置
`SCOPEGRAPH_MCP_ALLOW_SCAN_START=true` 后，Agent 才能对已确认根域启动 Quick/Standard
收集；MCP 永远不提供 Scope 批准、Deep、Custom、全端口或 Nuclei 工具。

Agent 连接后直接调用 `scopegraph_get_started` 即可获得实时健康状态、项目、权限、安全边界、
完整调用顺序和下一步参数，不需要预先读取仓库文档。随后调用
`scopegraph_all_in_one_snapshot`，可在一个 MCP 往返中并发取得 Scope、资产、网站、网络、发现项、
扫描历史和最新资产漏斗。

Docker MCP 地址为 <http://127.0.0.1:18001/mcp>。完整客户端配置、安全边界和工具清单见
[`docs/MCP.md`](./docs/MCP.md)。

## Docker Compose 启动

前置条件：Docker Desktop、Docker Compose v2。

Windows 日常使用可直接双击仓库根目录的 `Start-ScopeGraph.cmd`。它会检查并启动 Docker
Desktop、构建发生变化的镜像、拉起服务、同时确认 API 健康和 Web 项目页可访问，再自动使用
默认浏览器打开项目列表；不会删除数据库或扫描结果。若 Windows 的默认浏览器关联异常，脚本会
通过 Explorer 再尝试一次，并打印可直接打开的 URL。自动化启动可使用 `--no-open`，确认镜像未
变化时可用 `--no-build` 快速启动；它会保留匹配且健康的容器，避免中断正在执行的扫描；`--open`
可显式要求打开页面。

启动前可使用 `Start-ScopeGraph.cmd --check` 做不启动服务的 Docker/Compose/引擎预检；如果当前只
允许离线检查，使用 `Start-ScopeGraph.cmd --offline-check`，它只验证本地 CLI 和 Compose 配置，
不会连接 Docker、浏览器或任何扫描目标网络。

```powershell
Copy-Item .env.example .env
docker compose up -d --build
docker compose ps
```

首次启动会先等待 PostgreSQL，通过 Alembic 迁移后再启动 API、Worker 和 Web。健康后访问
<http://127.0.0.1:18080>。

API/Worker 镜像会从官方发布包构建并校验固定版本的 Subfinder、dnsx、httpx、Naabu、Nuclei、
Katana 与 AlterX，同时内置 PureDNS、MassDNS、Nmap、Chromium 和中文字体。无需再在 Windows
宿主机逐项安装工具；系统页应显示 `10/10` 兼容。

检查统一健康状态：

```powershell
docker compose exec api scopegraph doctor
docker compose exec api scopegraph doctor --json
```

核心 CLI 示例：

```powershell
docker compose exec api scopegraph project create --name "授权项目" --company "Example Inc." --root-domain example.com --authorized
docker compose exec api scopegraph project list --json
docker compose exec api scopegraph project delete <project-id> --yes
docker compose exec api scopegraph scope check <project-id> api.example.com --type domain --json
docker compose exec api scopegraph assets import <project-id> .\tests\fixtures\phase1_assets.json
docker compose exec api scopegraph assets list <project-id> --json
docker compose exec api scopegraph scan start <project-id> --root-domain example.com --authorized --json
docker compose exec api scopegraph scan start <project-id> --root-domain example.com --authorized --profile deep --confirm-deep --json
docker compose cp .\custom-profile.json api:/data/custom-profile.json
docker compose exec api scopegraph scan start <project-id> --root-domain example.com --authorized --profile custom --custom-config /data/custom-profile.json --json
docker compose exec api scopegraph scan list <project-id> --json
docker compose exec api scopegraph scan jobs <scan-run-id> --json
docker compose exec api scopegraph network ips <project-id> --json
docker compose exec api scopegraph network ports <project-id> --json
docker compose exec api scopegraph network classify <project-id> <ip-asset-id> --classification OWNED --reason "verified allocation" --json
docker compose exec api scopegraph enterprise discover <project-id> --mode fixture --json
docker compose exec api scopegraph root-domain list <project-id> --json
docker compose exec api scopegraph review list <project-id> --json
docker compose exec api scopegraph diff <project-id> --from <scan-a> --to <scan-b> --json
docker compose exec api scopegraph export create <project-id> --format xlsx --scope confirmed-and-high --json
```

Web 项目入口为 <http://127.0.0.1:18080/projects>。项目创建时必须显式确认已获得测试授权。
项目内提供 Scope、扫描、网络、网站、企业发现和安全/导出视图；系统页
<http://127.0.0.1:18080/system> 展示 10 个适配器的安装/兼容状态、存储用量、公开监听保护和
默认代理设置。截图失败不会阻止网站数据展示。

安装、升级、备份/恢复、兼容性、当前公开发布就绪状态和发布流程分别见 `docs/INSTALLATION.md`、
`docs/UPGRADE.md`、`docs/BACKUP_RESTORE.md`、`docs/COMPATIBILITY.md`、
`docs/PUBLIC_RELEASE_READINESS.md` 与 `docs/RELEASE_PROCESS.md`。非回环发布属于显式高级操作，必须同时
配置 `SCOPEGRAPH_PUBLIC_BIND=true` 和强随机 `SCOPEGRAPH_API_KEY`，客户端通过
`X-ScopeGraph-API-Key` 发送；代理 URL 禁止携带凭据。
Web 代理默认只接受 `localhost`、`127.0.0.1` 和 `::1` 的 Host；非回环部署还应设置
`SCOPEGRAPH_WEB_ALLOWED_HOSTS`（逗号分隔的主机名），代理会拒绝跨站写请求并限制请求体大小（默认 10 MiB）。

停止服务：

```powershell
docker compose down
```

如需同时删除本地开发数据库与队列卷，必须明确执行 `docker compose down -v`；这会删除
Compose 卷中的数据，日常停止不要使用。

## 本地开发

正式推荐 Docker。若本机已有 Python 3.12 与 Node.js 20.9+，也可分别运行：

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install --constraint constraints/python312.txt -e ".[dev]"
npm --prefix apps/web ci
```

启动依赖、迁移和应用：

```powershell
docker compose up -d db redis
$env:SCOPEGRAPH_DATABASE_URL = "postgresql+asyncpg://scopegraph:scopegraph@127.0.0.1:5432/scopegraph"
$env:SCOPEGRAPH_REDIS_URL = "redis://127.0.0.1:6379/0"
.\.venv\Scripts\alembic.exe upgrade head
.\.venv\Scripts\uvicorn.exe apps.api.main:app --reload
.\.venv\Scripts\dramatiq.exe apps.worker.tasks --processes 1 --threads 4
$env:API_INTERNAL_URL = "http://127.0.0.1:8000"
npm --prefix apps/web run dev
```

注意：Compose 默认不把数据库和 Redis 端口映射到宿主机。使用上面的混合开发命令时，
需在仅本机开发用的 Compose override 中显式绑定 `127.0.0.1`，不要绑定 `0.0.0.0`。

## 验证命令

```powershell
.\.venv\Scripts\python.exe -m ruff check apps scopegraph tests scripts
.\.venv\Scripts\python.exe -m mypy apps scopegraph
.\.venv\Scripts\python.exe -m pytest --cov=apps --cov=scopegraph
.\.venv\Scripts\python.exe scripts\validate_public_release.py --allow-dirty
npm --prefix apps/web run lint
npm --prefix apps/web run typecheck
npm --prefix apps/web run test
npm --prefix apps/web run build
docker compose config --quiet
python tests/integration/phase2_smoke.py
python tests/integration/phase3_smoke.py
python tests/integration/phase4_smoke.py
python tests/integration/phase5_smoke.py
python tests/integration/phase5_async_smoke.py
python tests/integration/phase6_smoke.py
python tests/integration/phase7_smoke.py
docker compose exec -T mcp python -m apps.mcp_server.smoke
```

CI 不访问真实互联网目标，也不调用任何安全工具。Compose 集成测试只使用仓库内固定 fixture。
Host 模式仅用于用户明确授权的目标；工具缺失或版本签名不匹配时任务会安全地标记为
`SKIPPED`。

## 目录

```text
apps/api/        FastAPI 入口
apps/worker/     Dramatiq Worker 入口
apps/cli/        Typer CLI 入口
apps/web/        Next.js Web
scopegraph/      Web、CLI、Worker 共享的核心 Python 代码
migrations/      Alembic 数据库迁移
configs/         扫描配置与规则的受控目录
tests/           单元、集成 fixture 与 E2E
data/            本地结构化文件、日志和后续扫描证据
```

阶段交付记录位于 `docs/PHASE_0_DELIVERY.md` 至 `docs/PHASE_7_RELEASE.md`；v1.0 总体验收和
已知边界见 [`RELEASE_NOTES_v1.0.0.md`](./RELEASE_NOTES_v1.0.0.md)。

面向校园演示的离线工作坊流程见 [`docs/CAMPUS_DEMO.md`](./docs/CAMPUS_DEMO.md)。
