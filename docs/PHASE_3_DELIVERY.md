# 阶段 3 交付记录

## 阶段名称

DNS、IP、端口和服务发现。

## 完成内容

- Quick、Standard、Deep 版本化 Profile 与封闭 Custom Schema，完整解析快照写入 ScanRun；
- AlterX 候选生成、PureDNS/MassDNS 验证与通配符过滤、dnsx 八类记录解析；
- Naabu 端口发现与 Nmap 轻量服务识别，Nmap 仅接收 Naabu 实际发现的端口；
- 多 IP Nmap 精确批处理，每个 IP 保持自己的开放端口集合，不使用扩大扫描面的端口并集；
- DNSRecord、IPDetail、Port、Service 专项表及 Alembic `0005_phase_three`；
- IP 安全分类：OWNED、CLOUD_SERVER、SHARED_HOSTING、CDN_WAF、UNKNOWN、PRIVATE_RESERVED；
- Scope + Profile + IP 分类三重端口策略；CDN/WAF 和私网/保留地址默认拒绝；
- 全端口 1–65535 仅允许 IN_SCOPE + OWNED，并要求单独请求和二次确认；
- IP 分类、端口与服务 API，含人工分类理由和审计日志；
- CLI `network ips/ports/classify` 与 scan 端口/全端口开关；
- Web IP/端口清单、分类表单、Profile 选择、端口开关和全端口二次确认；
- 完全离线 Phase 3 Compose 集成 smoke。

## 安全设计

- DNS 解析只建立关系，不自动证明 IP 所有权；人工 OWNED 分类必须附理由且 IP 已在 Scope；
- `ipaddress.is_global == false` 的地址锁定为 PRIVATE_RESERVED，不能人工解锁主动扫描；
- CDN CNAME 本地标记命中后分类为 CDN_WAF，端口策略直接拒绝；
- UNKNOWN/SHARED_HOSTING 最多保留 80、443、8080、8443；
- Profile、API 和 ToolAdapter 都拒绝任意 Shell 字符串及未知字段；
- Naabu 全端口用封闭 `-p -` 映射，不能由用户注入参数；
- Nmap 固定使用 `-Pn -sV --version-light --noninteractive`，不启用 NSE、`-A` 或 OS 探测；
- Nmap XML 限制大小并拒绝 DTD/ENTITY；内部批处理逐 IP 调用固定 argv；
- Worker 执行每个阶段前重新加载当前 Scope 与 IP 分类，修改 Scope 后旧快照不能越权。

## 自动验收结果

- Python：54 项单元测试通过；Ruff 通过；mypy strict 通过；
- Web：Vitest 7 项、ESLint、TypeScript 和 Next.js production build 通过；
- Alembic head：`0005_phase_three`，五个 Compose 服务健康；
- Phase 2 回归：Quick 三段链、历史 Observation、越界拒绝和指定 Job 重试全部通过；
- Phase 3 E2E：Subfinder → PureDNS → AlterX → PureDNS → dnsx → Naabu → Nmap → httpx
  八段 DAG 全部 SUCCESS，Profile 快照完整；
- PureDNS fixture 结果均标记已验证且已过滤 wildcard；
- CDN fixture IP 分类为 CDN_WAF，未进入 Naabu 输入；
- Naabu 输入只含 IN_SCOPE IP，并将发现的 80/443 精确传给 Nmap；
- 两条 Port 与两条 Service 记录可经 API 查询；
- Standard 端口关闭后不创建 Naabu/Nmap Job；
- 未二次确认的全端口请求返回 422；UNKNOWN IP 的全端口阶段被策略跳过；
- IP 人工标记 OWNED 并留存理由后，全端口请求才允许进入 Naabu。

## 验收命令

```powershell
.\.venv\Scripts\python.exe -m ruff check apps scopegraph tests
.\.venv\Scripts\python.exe -m mypy apps scopegraph
.\.venv\Scripts\python.exe -m pytest tests\unit
npm --prefix apps/web run test
npm --prefix apps/web run lint
npm --prefix apps/web run typecheck
npm --prefix apps/web run build
python tests/integration/phase2_smoke.py
python tests/integration/phase3_smoke.py
docker compose config --quiet
docker compose ps
```

## 已知限制

- Compose 镜像不捆绑外部安全工具；Host 模式需在受控运行环境中提供兼容版本；
- IP 分类的 ASN/组织/云厂商富化尚未接入离线数据库，目前主要依赖地址属性、CDN CNAME 和人工证据；
- DNS 字典目前为小型仓库内种子，Profile 上限已固化但尚未引入大规模授权字典包；
- 浏览器自动化运行时在本机初始化失败；Web 已通过静态审查、类型检查和生产构建，但本轮没有自动截图巡检；
- 覆盖置信度仍保持未评估，不会由 Job 100% 错误推断。

## 下一阶段依赖

阶段 4 在现有 URL、Port、Service 与证据链上增加 HTTP 指纹、TLS/证书、favicon、Webanalyze/Wappalyzer
技术识别和站点级快照。必须继续保持响应体大小上限、重定向上限、敏感字段脱敏和 Scope 重检。
