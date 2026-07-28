# ScopeGraph MCP 接入指南

ScopeGraph 内置官方 Python SDK 实现的 Model Context Protocol Server。外部 Agent 通过 MCP
读取本地项目、Scope、资产、网站、网络、发现项和扫描进度；管理员显式开启后，Agent 还可对
已确认根域启动受限的 Quick/Standard 信息收集。

连接后不需要先读本地文档：服务初始化说明会要求 Agent 首先调用
`scopegraph_get_started`。该工具一次返回实时健康状态、可见项目、当前写权限、安全边界、
完整推荐流程以及一组可直接用于下一次工具调用的 `recommended_next` 参数。MCP 还公开
`scopegraph_information_collection` prompt，供支持 MCP Prompts 的客户端直接装载操作流程。
拿到项目 ID 后，Agent 应优先调用 `scopegraph_all_in_one_snapshot`；它会在服务端并发读取 Scope、
资产、存活网站、IP/开放端口、发现项、历史和最近一次资产漏斗，减少多轮上下文往返。

## 默认安全边界

- MCP 不提供新增、确认、删除 Scope 的工具；
- 默认 `SCOPEGRAPH_MCP_ALLOW_SCAN_START=false`，所有工具只读；
- 开启 Agent 启动后仍只接受精确匹配的已确认根域；
- 不开放 Deep、Custom、全端口或 Nuclei；端口扫描默认关闭；
- Agent 收集默认不截图，避免大批站点拖慢主链；需要截图时显式传入 `include_screenshots=true`；
- Docker HTTP 端点只发布到 `127.0.0.1:8001`；
- 扫描完成度不代表攻击面覆盖率，自动发现项不代表已确认漏洞；
- `fixture` 结果会明确返回 `evidence_class=fixture`，不能当作真实证据。

## Docker / Streamable HTTP

启动全套服务：

```powershell
docker compose up -d --build
docker compose ps
```

本机 MCP 地址：`http://127.0.0.1:8001/mcp`。

只有在本地管理员希望 Agent 能启动扫描时，才在 `.env` 中加入：

```dotenv
SCOPEGRAPH_MCP_ALLOW_SCAN_START=true
```

修改后执行 `docker compose up -d mcp`。这个开关是管理员对 MCP 写操作的本地授权，不会放宽
项目 Scope；项目仍需先在 Web 中确认根域。

## stdio 接入

stdio 不开放监听端口，适合由 Agent 客户端直接启动。确保 API 已运行，然后配置客户端命令：

```json
{
  "mcpServers": {
    "scopegraph": {
      "command": "scopegraph-mcp",
      "args": ["--transport", "stdio"],
      "env": {
        "SCOPEGRAPH_API_URL": "http://127.0.0.1:8000",
        "SCOPEGRAPH_MCP_ALLOW_SCAN_START": "false"
      }
    }
  }
}
```

如果通过本仓库虚拟环境运行，将 `command` 改为虚拟环境里的 `scopegraph-mcp` 绝对路径。

## Streamable HTTP 客户端配置示例

支持 HTTP MCP 的 Agent 使用：

```json
{
  "mcpServers": {
    "scopegraph": {
      "type": "http",
      "url": "http://127.0.0.1:8001/mcp"
    }
  }
}
```

不同 Agent 的配置字段可能略有不同，以其 MCP 客户端文档为准。不要把 Docker 端口改成
`0.0.0.0` 直接暴露到局域网或公网；跨机器使用时应部署受认证的反向代理/OAuth 资源服务器。

## 工具清单

| 工具 | 作用 | 默认权限 |
|---|---|---|
| `scopegraph_get_started` | 连接即用的实时向导、项目和下一步参数 | 只读 |
| `scopegraph_system_status` | API 与依赖健康状态 | 只读 |
| `scopegraph_list_projects` | 项目列表 | 只读 |
| `scopegraph_project_overview` | 项目摘要和 Scope 规则 | 只读 |
| `scopegraph_all_in_one_snapshot` | 一次取得完整的有界项目信息快照与资产漏斗 | 只读 |
| `scopegraph_check_scope` | 服务端 Scope 判定 | 只读 |
| `scopegraph_list_assets` | 分页资产查询 | 只读 |
| `scopegraph_list_websites` | 网站列表 | 只读 |
| `scopegraph_website_detail` | 网站证据详情 | 只读 |
| `scopegraph_network_inventory` | IP/端口查询 | 只读、限制返回量 |
| `scopegraph_list_findings` | 低风险发现项 | 只读 |
| `scopegraph_list_scan_runs` | 扫描历史 | 只读 |
| `scopegraph_scan_run_detail` | 实时阶段、错误和事件 | 只读 |
| `scopegraph_start_collection` | 启动受限收集 | 默认关闭 |
| `scopegraph_cancel_collection` | 取消 Agent 扫描并保留证据 | 默认关闭 |

推荐 Agent 流程：连接后调用 `scopegraph_get_started` → 按 `recommended_next` 调用
`scopegraph_all_in_one_snapshot` → 检查目标 Scope → 必要时启动收集 → 使用返回的 run id 轮询
扫描详情 → 再次读取 All-in-One 快照。扫描摘要中的资产漏斗和并行节省时间可直接用于判断本次
收集相对单独运行 Subfinder 增加了哪些已验证结果。

## 验证

Docker MCP 服务启动后可在容器内运行官方 SDK 客户端 smoke：

```powershell
docker compose exec -T mcp python -m apps.mcp_server.smoke
```

管理员开启 Agent 扫描后，可用已确认项目和根域验证完整的“启动 → 轮询 → 终态”链路：

```powershell
docker compose exec -T mcp python -m apps.mcp_server.collection_smoke `
  --project-id <PROJECT_ID> --root-domain example.com --execution-mode fixture --confirm-start
```

如果客户端进程中断，扫描不会丢失；使用返回的 run id 继续通过 MCP 轮询：

```powershell
docker compose exec -T mcp python -m apps.mcp_server.poll_smoke --run-id <SCAN_RUN_ID>
```

也可使用 MCP Inspector 连接 `http://127.0.0.1:8001/mcp`。
