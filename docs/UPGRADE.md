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

## 回退原则

应用镜像可回退到备份标签，但数据库降级不是默认安全操作。若迁移后出现问题，停止服务并从
同一时间点的数据库、Redis、文件三件套恢复。不要只恢复数据库，否则原始证据路径和队列状态
可能不一致。

