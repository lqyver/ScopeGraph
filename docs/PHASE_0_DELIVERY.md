# 阶段 0 交付记录

## 阶段名称

仓库、基础设施和工程规范。

## 完成内容

- FastAPI、Dramatiq Worker、Typer CLI、Next.js 最小服务；
- PostgreSQL、Redis、数据库迁移和 Docker Compose；
- JSON 结构化日志、请求 ID、统一错误响应；
- `/health`、`/api/v1/system/health` 和 `scopegraph doctor`；
- Python/TypeScript lint、类型检查、单元测试和生产构建；
- GitHub Actions CI 与本地启动说明。

## 新增文件/迁移

- `migrations/versions/0001_phase_zero_system_metadata.py`：创建系统元数据表并记录当前 Schema 阶段；
- `docker-compose.yml`：编排 Web、API、Worker、PostgreSQL、Redis 与一次性迁移服务；
- `apps/web/package-lock.json`：锁定已审计的前端依赖树。

## 启动命令

```powershell
Copy-Item .env.example .env
docker compose up -d --build
```

默认入口为 <http://127.0.0.1:8080>，API 为 <http://127.0.0.1:8000>。

## 测试命令与结果

- Ruff：通过；
- mypy strict：通过，15 个 Python 源文件无错误；
- pytest：7 项通过，覆盖率 62%；
- ESLint：通过；
- TypeScript：通过；
- Vitest：3 项通过；
- Next.js production build：通过；
- `npm audit --omit=dev`：0 个已知生产依赖漏洞；
- Docker Compose：API、Web、Worker、PostgreSQL、Redis 均为 `healthy`；
- `scopegraph doctor --json`：API、数据库、Redis、本地存储均为 `healthy`。

## 手工验收步骤

1. 打开 Web，确认显示“阶段 0 · 基础系统”和四项本地运行状态；
2. 确认页面分别展示“任务执行完成度”和“攻击面覆盖置信度”；
3. 执行 `docker compose exec api scopegraph doctor --json`；
4. 执行 `docker compose ps`，确认五个常驻服务健康；
5. 确认宿主机只监听 `127.0.0.1:8080` 和 `127.0.0.1:8000`。

## 未完成内容

阶段 1 及后续功能均未提前实现：项目 CRUD、Scope 引擎、资产表、真实扫描任务和外部工具
适配器当前不存在。

## 已知问题

- 当前健康检查验证基础运行时，不检查后续阶段才引入的外部安全工具版本；
- 当前测试覆盖率是阶段 0 骨架覆盖率，阶段 1 需要为项目、Scope 和规范化逻辑设置更高门槛；
- 第一版仍是单机本地系统，不包含认证、团队协作或定时扫描。

## 安全约束验证

- 阶段 0 不产生主动探测流量；
- Web 仅绑定 `127.0.0.1:8080`，API 仅绑定 `127.0.0.1:8000`；
- Worker 只有无网络探测的 heartbeat actor；
- Worker 健康检查只验证本地 Redis 队列连接；
- 未提供任意 Shell 参数入口；
- 任务完成度与攻击面覆盖置信度在 Web 中明确分开展示。

## 下一阶段依赖

进入阶段 1 前，应以本阶段 CI 全绿、Compose 全部健康为门槛。阶段 1 将实现项目、Scope 与
资产核心，不接入真实外部扫描工具。
