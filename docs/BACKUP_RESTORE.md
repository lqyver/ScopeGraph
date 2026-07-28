# ScopeGraph 备份与恢复

ScopeGraph 的一致备份包含 PostgreSQL、Redis AOF 和 `scopegraph_data` 三部分。建议在没有运行
扫描时执行，并记录版本和 Alembic revision。

## 备份

```powershell
New-Item -ItemType Directory -Force .\backup
docker compose exec -T db pg_dump -U scopegraph -d scopegraph -Fc -f /tmp/scopegraph.dump
docker compose cp db:/tmp/scopegraph.dump .\backup\scopegraph.dump
docker compose exec -T redis redis-cli SAVE
docker compose exec -T redis tar czf /tmp/redis.tgz -C /data .
docker compose cp redis:/tmp/redis.tgz .\backup\redis.tgz
docker compose exec -T api tar czf /tmp/files.tgz -C /data .
docker compose cp api:/tmp/files.tgz .\backup\files.tgz
docker compose run --rm migrate alembic current
```

上述命令通过 Compose 服务复制文件，不依赖卷前缀。备份目录应加密并限制访问，因为原始证据
可能包含敏感元数据。

## 恢复

在隔离环境验证备份后，停止应用服务，创建全新的空卷，恢复 `files.tgz` 和 `redis.tgz`，再将
PostgreSQL dump 导入空数据库：

```powershell
docker compose stop api worker web
docker compose exec -T db dropdb -U scopegraph --if-exists scopegraph
docker compose exec -T db createdb -U scopegraph scopegraph
docker compose cp .\backup\scopegraph.dump db:/tmp/scopegraph.dump
docker compose exec -T db pg_restore -U scopegraph -d scopegraph --clean --if-exists /tmp/scopegraph.dump
docker compose cp .\backup\files.tgz api:/tmp/files.tgz
docker compose exec -T api tar xzf /tmp/files.tgz -C /data
docker compose cp .\backup\redis.tgz redis:/tmp/redis.tgz
docker compose exec -T redis tar xzf /tmp/redis.tgz -C /data
docker compose up -d
docker compose exec api scopegraph doctor --json
```

恢复后核对 Alembic revision、项目数、最近 ScanRun、导出哈希和文件数量。结构化历史与文件必须
来自同一备份窗口。
