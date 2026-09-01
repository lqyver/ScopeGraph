# 阶段 2 交付记录

## 阶段名称

工具框架和首条扫描链。

## 完成内容

- ScanRun、ScanJob、FileArtifact 模型、状态机、进度聚合和显式 DAG 顺序；
- ToolAdapter 基类与不可变 Manifest，覆盖存在性、版本签名、输入 Schema 和 argv 白名单；
- 无 Shell 异步进程执行器，支持超时、取消、独立进程组和每次尝试的证据目录；
- stdout/stderr 原始文件、SHA-256、大小、媒体类型和数据库索引；
- Subfinder、dnsx、ProjectDiscovery httpx 适配器及 JSONL 解析器；
- 根域 → Subfinder → dnsx → httpx 队列 DAG 与统一 Observation 写入；
- Observation → Asset/AssetRelation 幂等归并，跨 ScanRun 保留历史；
- 创建、查询、暂停、恢复、取消、重试和事件快照 API；
- CLI `scan start/list/show/jobs/pause/resume/cancel/retry`；
- Web 扫描任务中心，明确区分任务完成度和攻击面覆盖置信度；
- 完全离线 Compose 集成 smoke，可在 CI 重复执行。

## 新增文件/迁移

- `migrations/versions/0003_phase_two_scan_runtime.py`：ScanRun、ScanJob、FileArtifact 与 Observation 外键；
- `migrations/versions/0004_phase_two_dag_order.py`：显式 Job sequence、检查和唯一约束；
- `scopegraph/tooling/`：适配器、Manifest、安全进程执行和内置 fixture；
- `scopegraph/scanning/`：状态机、幂等键和统一 Observation Schema；
- `scopegraph/application/services/scan_execution.py`：Worker DAG 执行与结构化归并；
- `apps/web/app/projects/[id]/scans/`：任务中心；
- `tests/integration/phase2_smoke.py`：回环地址上的离线 Compose 验收。

## 启动命令

```powershell
docker compose up -d --build
docker compose ps
```

Web 任务中心：`http://127.0.0.1:18080/projects/<project-id>/scans`。

## 测试命令

```powershell
.\.venv\Scripts\python.exe -m ruff check apps scopegraph tests
.\.venv\Scripts\python.exe -m mypy apps scopegraph
.\.venv\Scripts\python.exe -m pytest --cov=apps --cov=scopegraph
npm --prefix apps/web run lint
npm --prefix apps/web run typecheck
npm --prefix apps/web run test
npm --prefix apps/web run build
python tests/integration/phase2_smoke.py
docker compose config --quiet
```

## 测试结果

- Ruff：通过；mypy strict：通过；
- pytest：40 项通过，含状态机、解析器、命令白名单、超时、取消和路径穿越测试；
- ESLint、TypeScript、Vitest 7 项、Next.js production build：通过；
- Alembic：`0004_phase_two_order`，`system_metadata.schema_phase=2`；
- 离线队列 E2E：3 个 Job 按 0/1/2 顺序成功，7 条 Observation，进度 100%；
- 第二个 ScanRun：新增 7 条历史 Observation、0 个重复资产；
- 出域根域：入队前返回 403 `SCOPE_VIOLATION`；
- Host 缺工具：Subfinder/dnsx 为 `TOOL_UNAVAILABLE`，Python httpx 名称冲突为
  `TOOL_INCOMPATIBLE`，均未当作 ProjectDiscovery 工具执行。
- 连续 Actor/指定 Job 重试：Subfinder/dnsx 保持 attempt 1，仅 httpx 到 attempt 2，证据写入
  `/attempts/2/`；每个 Actor 的独立异步连接池在原事件循环内释放。

## 手工验收步骤

1. 打开项目任务中心，选择“离线 fixture”，确认授权后创建任务；
2. 确认 Job 固定按 Subfinder、dnsx、httpx 顺序运行并达到 `SUCCESS`；
3. 展开 Job，确认 stdout/stderr 路径可追溯且位于系统生成的 ScanRun/Job/attempt 目录；
4. 再创建相同任务，确认资产新增为 0，但新 ScanRun 有自己的 Observation 历史；
5. 尝试创建 `outside.example.net`，确认返回 403 且未产生 ScanRun；
6. 在未安装 ProjectDiscovery 工具的容器选择 Host 模式，确认安全降级为 `SKIPPED`；
7. 使用 CLI 查询 ScanRun 和 Job JSON，确认与 Web/API 状态一致；
8. 运行 `python tests/integration/phase2_smoke.py` 完成可重复回环验收。

## 已知问题

- Compose 镜像不捆绑 ProjectDiscovery 工具，Host 模式需用户单独提供兼容安装；
- 当前事件接口为可轮询 JSON 快照，尚未升级为 SSE/WebSocket 流；
- 当前第一条链只建立通用 Asset/Relation/Observation，DNS/Web 专项详情表在后续阶段实现；
- 覆盖置信度在阶段 2 保持“未评估”，不会由任务 100% 推断；
- Worker 并发目前为单进程四线程，尚未进行阶段 7 的高规模性能调优。

## 安全约束验证

- API 入队前和 Worker 执行前均重新计算 Scope，排除规则始终优先；
- Host 执行要求项目授权、每次任务授权和主动执行三项显式确认；
- 进程执行只使用 argv 数组，不接受用户 Shell 字符串；
- 工具参数来自封闭 Pydantic Schema 和适配器白名单；
- 文件路径只由 Project/ScanRun/Job UUID 和受控文件名生成；
- 每次重试使用独立 attempt 目录，旧原始证据不会被覆盖；
- 工具缺失、版本不兼容、超时、非零退出和解析错误有不同错误码；
- 单个阶段失败不删除既有结果，原始输出始终保留；
- CI 与默认 fixture 模式不访问公网。

## 下一阶段依赖

阶段 3 复用现有 ToolAdapter、ScanJob、FileArtifact 和双 Scope 门禁，增加 PureDNS/dnsx、
Naabu/Nmap 及 DNS/IP/Port/Service 专项表。接入前必须先补录制 fixture、解析器测试、私网/CDN
分类和端口/速率上限；真实验收仍仅允许明确授权的回环或受控靶场。
