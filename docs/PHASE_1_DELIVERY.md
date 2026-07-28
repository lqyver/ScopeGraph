# 阶段 1 交付记录

## 阶段名称

项目、Scope 和资产核心。

## 完成内容

- Project、ScopeRule、Asset、AssetRelation、Observation、Evidence、AuditLog 数据模型；
- 项目创建、查询、更新、软删除和摘要 API；
- Scope 包含/排除规则、规范化、匹配优先级和主动任务硬门禁；
- 公司名、域名、IP、CIDR、URL 规范化及稳定资产唯一键；
- UTF-8 TXT、CSV、JSON 种子资产导入，逐项拒绝错误和幂等去重；
- Web 项目列表、新建授权项目、Scope 管理/检查、资产导入和资产表；
- Typer CLI 项目、Scope 和资产命令；
- 项目、Scope、导入操作的审计日志。

## 新增文件/迁移

- `migrations/versions/0002_phase_one_core.py`：创建阶段 1 核心表、索引、唯一约束并将 Schema 阶段更新为 1；
- `scopegraph/normalizers/`：资产和导入规范化；
- `scopegraph/scope_engine/`：Scope 匹配与主动任务门禁；
- `scopegraph/application/services/projects.py`：项目、规则和资产用例；
- `apps/api/routers/projects.py`：阶段 1 REST API；
- `apps/web/app/projects/`：项目和 Scope 页面；
- `tests/fixtures/phase1_assets.json`：离线验收 fixture。

## 启动命令

```powershell
Copy-Item .env.example .env
docker compose up -d --build
docker compose ps
```

默认 Web 入口为 <http://127.0.0.1:8080/projects>，API 文档为
<http://127.0.0.1:8000/docs>。

## 测试命令

```powershell
.\.venv\Scripts\python.exe -m ruff check apps scopegraph tests
.\.venv\Scripts\python.exe -m mypy apps scopegraph
.\.venv\Scripts\python.exe -m pytest --cov=apps --cov=scopegraph
npm --prefix apps/web run lint
npm --prefix apps/web run typecheck
npm --prefix apps/web run test
npm --prefix apps/web run build
npm --prefix apps/web audit --omit=dev
docker compose config --quiet
```

## 测试结果

- Python Ruff：通过；
- mypy strict：通过；
- pytest：26 项通过；
- ESLint 与 TypeScript：通过；
- Vitest：7 项通过；
- Next.js production build：通过；
- 生产前端依赖审计：0 个已知漏洞；
- Alembic：`0002_phase_one`，`system_metadata.schema_phase=1`；
- Compose：API、Web、Worker、PostgreSQL、Redis 全部健康；
- 实库双次导入：首次创建 4/拒绝 1，第二次创建 0/重复 4/拒绝 1，数据库保持 4 个唯一资产。

## 手工验收步骤

1. 打开 `/projects/new`，不勾选授权确认时确认不能提交；
2. 创建含根域和排除域的项目，进入 Scope 页面；
3. 检查同根子域为 `IN_SCOPE`、排除域为 `EXCLUDED`、其他目标为 `OUT_OF_SCOPE`；
4. 导入 `tests/fixtures/phase1_assets.json` 两次，确认第二次不新增资产；
5. 核对域名转小写且去尾点、URL 移除默认端口/片段并规范路径；
6. 用 CLI 重复项目列表、Scope 检查和资产列表查询；
7. 更新并软删除一个临时项目，确认常规列表不再返回它且数据库保留审计记录。

## 已知问题

- 当前仍是单机本地系统，不包含认证、团队/RBAC 或多租户隔离；
- 资产导入只接受不超过 10 MiB 的 UTF-8 TXT/CSV/JSON；
- 归属评分在阶段 1 仅依据用户确认的 Scope，企业识别和多源证据留到阶段 5；
- 扫描运行、工具适配器和任务中心属于阶段 2，当前没有真实扫描能力。

## 安全约束验证

- 创建项目必须提交显式授权确认；
- 显式排除规则优先于包含规则；
- 未匹配目标默认为 `OUT_OF_SCOPE`，不会被静默纳入；
- 主动任务门禁拒绝 `EXCLUDED` 和 `OUT_OF_SCOPE` 目标；
- Scope 外、第三方和未知资产不会派生主动任务；
- 本阶段没有外部安全工具调用，不产生网络探测流量；
- Web/API 仅绑定回环地址，数据库和 Redis 不暴露宿主机端口。

## 下一阶段依赖

阶段 2 必须复用本阶段的稳定资产键、Scope 门禁和审计机制。任何 ToolAdapter 只能接收结构化
参数；任务创建和 Worker 执行前都必须再次校验 Scope。首条扫描链应先使用本地/录制 fixture
验证失败隔离、取消、超时、原始证据和幂等写入，再对明确授权的回环或受控目标做验收。
