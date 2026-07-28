# 阶段 4 交付记录

## 阶段名称

网站体验、受控爬虫、截图与备案证据。

## 完成内容

- Alembic `0006_phase_four` 及 Website、WebSnapshot、Certificate、Technology、Endpoint、
  ICPRecord、WebsiteICPLink 专项表；
- httpx 完整 Web 观察：输入/最终 URL、同主机跳转链、状态、标题、内容类型/长度、响应时间、
  IP/端口、CNAME、Server、技术栈、CDN/WAF、TLS、favicon 和页面哈希；
- 响应头采用安全保留清单，`Set-Cookie` 等敏感字段不进入结构化数据库；页面正文仅以最多
  256 KiB 的有界 preview 在适配器内提取备案，不写入 Observation；
- 独立 ScreenshotAdapter：截图失败只影响截图 Job，不回滚 httpx 已入库网站；路径由系统生成，
  拒绝绝对路径和 `..`，图片读取再次校验数据根目录边界；
- KatanaAdapter：FQDN Scope、外链只展示、GET/HEAD 安全访问、固定深度/时长/页面数/响应体/
  并发/速率；不启用自动填表、认证头、Cookie、Headless 表单或任意自定义参数；
- 新域名反馈：外部 URL、主机与 registrable root 一并进入 `PENDING_REVIEW`，不动态创建后续
  DNS、端口或 Web 扫描任务；
- ICP 与公安备案提取器：忽略 script/style/template，支持页面可见文本、meta、去重、证据摘录
  和版权主体提取；
- 页面直接备案使用 `PAGE_DIRECT`；同 registrable root 的其他网站只建立
  `ROOT_DOMAIN_INFERRED` 关系，直接证据和推断证据不混用；
- 版本化第三方 CNAME 规则：CDN 目标为 `CDN_SHARED`，SaaS 目标为 `THIRD_PARTY`，显式 Scope
  与排除规则优先，第三方目标不扩展主动扫描；
- 网站、详情、备案、端点 REST API，以及受目录约束的截图读取接口；
- Web 网站截图墙/表格切换、搜索、统计、截图失败占位、网站详情、TLS、备案证据、端点边界、
  外部根域待审核提示和响应式布局。

## 安全设计验证

- httpx 仅使用参数数组，拒绝任意字段；只跟随同主机跳转，并通过 `-deny` 阻止私网、回环、
  link-local、组播和 IPv6 ULA；
- httpx 不使用 POST body、unsafe、认证文件或云上传参数；备案提取不持久化响应正文；
- Katana 使用 `-fs fqdn -do`：外部端点可作为证据输出，但不会被跟随；POST/PUT/PATCH/
  DELETE 记录强制 `actively_visited=false`；
- Screenshot Job 独立于 Website 持久化；Fixture 明确模拟一个成功截图和一个失败截图，两个网站
  均正常入库；浏览器使用无持久化的默认隔离会话，并关闭后台网络、扩展、同步和组件更新；
- 直接/推断备案使用不同枚举和多对多记录，API 与 Web 均显示证据类型；
- 新外部根域只标记待审核；扫描计划在 Katana 后结束，没有自动反馈到 DNS/端口任务；
- 第三方 CNAME 只改变目标资产状态，不改变来源域名 Scope，也不把第三方目标送入 Naabu。

## API 与页面

- `GET /api/v1/projects/{id}/websites`；
- `GET /api/v1/websites/{id}`；
- `GET /api/v1/websites/{id}/screenshot`；
- `GET /api/v1/projects/{id}/icp-records`；
- `GET /api/v1/projects/{id}/endpoints`；
- Web：`/projects/{id}/websites`、`/websites/{id}`。

## 自动验收结果

- Python：63 项单元测试通过；Ruff 全仓通过；mypy strict 覆盖 66 个源码文件通过；
- Web：Vitest 9 项、ESLint、TypeScript 全部通过；Docker 内 Next.js production build 成功；
- 数据库：Alembic head 为 `0006_phase_four`；API、Worker、Web、PostgreSQL、Redis 五个服务健康；
- Phase 2 回归：三段最小链、越界拒绝、幂等复扫和单 Job 重试通过；
- Phase 3 回归：DNS/端口/服务、CDN 禁止、端口关闭和全端口双确认通过；
- Phase 4 E2E：十段 DAG 全部 SUCCESS；2 个网站、2 条备案、5 个端点正确落库；
- 网站 A 页面直接提取两条备案，网站 B 仅根域推断；API 保持 `PAGE_DIRECT` 与
  `ROOT_DOMAIN_INFERRED` 区分；
- 截图成功文件能通过安全图片接口读取；另一个截图失败但网站仍存在；
- 外部 `example.net` 根域和主机为 `PENDING_REVIEW`，POST 端点未被标记为实际访问；
- CloudFront CNAME 目标为 `CDN_SHARED/THIRD_PARTY`；第二次扫描不重复创建项目级网站或备案。

## 验收命令

```powershell
.\.venv\Scripts\python.exe -m ruff check apps scopegraph tests
.\.venv\Scripts\python.exe -m mypy apps scopegraph
.\.venv\Scripts\python.exe -m pytest tests\unit -q
.\.venv\Scripts\python.exe tests\integration\phase2_smoke.py
.\.venv\Scripts\python.exe tests\integration\phase3_smoke.py
.\.venv\Scripts\python.exe tests\integration\phase4_smoke.py
npm --prefix apps/web run test
npm --prefix apps/web run lint
npm --prefix apps/web run typecheck
docker compose build web
docker compose config --quiet
docker compose ps
docker compose exec -T api python -m alembic current
```

## 已知限制

- Compose Python 镜像仍不捆绑 ProjectDiscovery/Nmap 工具；Fixture 模式完整可验收，Host 模式
  需在受控环境中安装兼容工具和 system Chrome；
- ICP 页面提取基于最多 256 KiB 的 body preview；超大页面且备案只位于更后位置时可能需要人工
  核验，系统不会编造记录；
- 第三方 CNAME 规则是保守本地后缀表，不替代 ASN/厂商在线数据库；未命中目标保持待审核；
- 本机 Windows UI 自动化运行组件初始化失败；已完成代码级响应式/无障碍审查、HTTP 页面检查和
  Docker production build，但本阶段没有自动化浏览器截图巡检；
- 本记录保留阶段 4 当时的验收边界；企业发现、审核和覆盖评估已在阶段 5 完成。

## 下一阶段依赖

阶段 5 应复用 `PENDING_REVIEW` 根域、备案主体、版权主体、CNAME 分类和现有 Evidence/AuditLog，
实现企业名称规范化、公开页面 Source Adapter、可解释归属评分、人工覆盖与覆盖置信度。任何
自动分数不得绕过人工 Scope 确认。
