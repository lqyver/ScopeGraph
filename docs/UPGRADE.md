# ScopeGraph 升级

## 升级前

1. 停止创建新扫描，等待运行任务结束或显式取消；
2. 按 `BACKUP_RESTORE.md` 同时备份 PostgreSQL、Redis 和 `scopegraph_data`；
3. 保存当前镜像标签、`.env` 和 `docker compose config` 输出；
4. 阅读目标版本发布说明和数据库迁移。

## 升级步骤

```powershell
docker compose pull
docker compose build --pull
docker compose run --rm migrate alembic upgrade head
docker compose up -d
docker compose ps
docker compose exec api scopegraph doctor --json
docker compose run --rm migrate alembic current
```

再运行项目内 Phase 7 smoke。工具升级由操作者单独完成；先在系统页检查版本，不兼容时保持
原版本或更新适配器，禁止绕过签名检查。

Community Edition 的 `0010_scan_run_execution_mode` 迁移会把扫描证据模式从
`config_snapshot` 同步到 `scan_runs.execution_mode`，并建立项目/模式/时间索引。升级时必须先执行
`docker compose run --rm migrate alembic upgrade head`，不要手工删除或重建 `scan_runs`；迁移完成后，
历史记录默认回填为快照中的模式，缺失模式的旧记录回填为 `host`。

## 回退原则

应用镜像可回退到备份标签，但数据库降级不是默认安全操作。若迁移后出现问题，停止服务并从
同一时间点的数据库、Redis、文件三件套恢复。不要只恢复数据库，否则原始证据路径和队列状态
可能不一致。

## 从早期 Community 候选版迁移

早期 Community 候选版使用 Compose 项目名 `scopegraph`；当前默认项目名是
`scopegraph-community`。Compose 会据此创建一组新的卷，旧数据库、Redis 和文件数据不会自动
迁移。如果本机从未运行过早期 Community 候选版，则无需执行本节。

切换前停止创建新扫描并等待现有任务结束。检查旧栈时显式选择原项目：

```powershell
docker compose -p scopegraph ps
```

备份时，对 `BACKUP_RESTORE.md` 中的每条 `docker compose` 命令添加 `-p scopegraph`，将
PostgreSQL、Redis 和 `scopegraph_data` 保存为同一时间点的数据集。不要对旧项目执行
`docker compose -p scopegraph down -v`，否则会删除待迁移卷。

备份完成后，以默认的 `scopegraph-community` 项目启动新版，再按照 `BACKUP_RESTORE.md` 恢复
全部三部分数据。确认新版项目数、最近扫描、导出哈希和文件数量完整，并验证备份可恢复后，再
单独决定何时清理旧卷。

