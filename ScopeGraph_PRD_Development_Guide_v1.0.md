# ScopeGraph 企业公网攻击面发现平台

## 产品需求与开发实现指南 v1.0

**文档用途：** 直接交给开发 Agent，作为产品设计、系统实现、测试和分阶段交付的唯一主规格。  
**产品形态：** 本地 CLI + 本地 Web 平台。  
**目标用户：** 具备合法授权的网络安全工程师，第一版以个人使用为主。  
**核心原则：** 本地运行、本地存储、零强制商业 API、公开数据源可选、主动探测受 Scope 严格约束。

---

# 0. 给开发 Agent 的执行规则

本节优先级高于后续所有实现建议。

1. **按阶段开发，不允许一次性实现整个系统。** 每个阶段必须先完成代码、自动化测试、基础文档和验收，再进入下一阶段。
2. **所有外部安全工具都通过适配器调用。** 业务代码不得散落硬编码命令行参数，也不得依赖终端彩色文本解析。
3. **优先使用工具的 JSON、JSONL、XML 等结构化输出。** 如果当前版本不支持，再实现受版本约束的文本解析器。
4. **每个工具运行前必须读取并记录工具版本。** 未通过兼容性检查的版本不得静默执行。
5. **任何新发现资产必须先经过规范化、去重、Scope 判断和归属判断，再决定是否派生主动扫描任务。**
6. **Scope 外、第三方和 CDN/WAF 资产不得被自动主动扫描。**
7. **不得使用 `shell=True`，不得将用户输入直接拼入 Shell 命令。** 所有参数使用数组调用、白名单校验和严格类型验证。
8. **单个工具失败不得导致整个项目失败。** 保存原始输出和错误日志，将阶段标记为“部分成功”或“失败”，允许重试。
9. **数据库写入必须幂等。** 相同资产、关系、观察结果和任务不得因重试重复生成。
10. **Web 与 CLI 共用同一套核心服务、数据库和任务系统。** 不维护两套业务逻辑。
11. **实现过程中如遇非阻断性歧义，按本文默认值执行。** 只有会造成数据损坏、越权扫描或架构无法继续的情况才需要询问用户。
12. **产品不承诺发现企业全部资产。** 界面必须区分“任务执行完成度”和“攻击面覆盖置信度”。
13. **第一版不实现 AI。** 只预留插件接口，AI 不得参与 Scope 自动批准或高风险任务授权。
14. **开发 Agent 每个阶段结束时必须输出：** 已完成内容、未完成内容、已知问题、测试结果、启动方式、下一阶段建议。

---

# 1. 产品概述

## 1.1 产品定位

ScopeGraph 是一款面向授权渗透测试和企业公网资产梳理的本地攻击面发现平台。用户输入企业名称，系统尝试识别企业主体、候选官方网站和根域名；用户确认 Scope 后，平台自动编排开源工具，发现并关联：

- 根域名与子域名；
- DNS 记录、CNAME 和 TLS 证书；
- IP、端口和网络服务；
- 存活 Web 网站、截图和技术栈；
- CDN、WAF、云服务和第三方托管关系；
- ICP 备案号、公安备案号、页面版权主体；
- 低风险安全暴露和错误配置；
- 多次扫描之间的资产变化。

系统最终输出的不是工具日志，而是一份带有来源、证据、Scope 状态、归属评分和历史变化的企业公网攻击面资产库。

## 1.2 产品目标

第一版必须实现：

1. 允许只输入企业名称创建项目。
2. 尝试发现候选官网、候选根域名和备案信息；失败时要求用户补充根域名。
3. 支持用户确认、排除和补充根域名，生成明确 Scope。
4. 提供快速、标准、深度和自定义四种扫描模式。
5. 整合 Subfinder、AlterX、PureDNS、MassDNS、dnsx、Naabu、httpx、Nmap、Katana、Nuclei。
6. 深度模式可选整合 Amass、gau、waybackurls。
7. 对所有工具结果进行统一标准化、去重、关系构建和证据保存。
8. 提供项目总览、资产表、IP/端口表、网站截图墙、网站详情、备案信息、待审核中心、安全发现和历史对比。
9. 提供 CLI 和 Web 两种操作入口。
10. 支持 Excel、CSV、JSON、HTML 和 Markdown 导出。
11. 所有数据和原始文件默认保存在本地。
12. 可在 Kali Linux、Windows Docker Desktop 和 WSL2 环境运行。

## 1.3 非目标

第一版明确不做：

- 不保证发现企业全部公网资产；
- 不自动绕过验证码、登录、访问控制或反爬机制；
- 不自动执行破坏性漏洞利用；
- 不默认执行密码爆破、数据修改、文件上传、命令执行或 DoS 测试；
- 不自动扫描 Scope 外、第三方平台或共享 CDN 基础设施；
- 不将 Nuclei 命中直接认定为已确认漏洞；
- 不覆盖内网、分裂 DNS 和仅 VPN 可访问资产；
- 不强制依赖 FOFA、Shodan、Censys 或企业信息商业 API；
- 不在第一版实现团队协作、复杂 RBAC 和云端 SaaS；
- 不在第一版实现定时周期扫描；所有扫描由用户手动启动。

---

# 2. 用户、环境与约束

## 2.1 用户角色

第一版只有一个本地管理员用户：

- 创建和管理项目；
- 配置 Scope 和排除规则；
- 启动、暂停、取消和重试任务；
- 审核候选资产；
- 查看、筛选和导出结果；
- 管理工具、字典、模板、代理和存储。

不实现多人权限，但数据库表预留 `created_by`、`updated_by` 字段。

## 2.2 支持环境

优先支持：

1. Kali Linux：支持 Docker 模式，也允许识别宿主机已有工具。
2. Windows：推荐 Docker Desktop；也支持 WSL2。
3. 普通个人电脑：建议至少 4 核 CPU、8 GB 内存、50 GB 可用磁盘；推荐 8 核、16 GB 内存。

系统默认通过 Docker Compose 部署。Web 默认监听 `127.0.0.1`。如果用户绑定局域网地址，必须启用本地账号密码。

## 2.3 网络条件

- 允许访问公共 DNS、HTTP、HTTPS 和公开搜索页面；
- 不要求用户配置付费商业 API；
- 公开数据源需要账号或 Token 时，作为可选插件，不影响主流程；
- 支持全局代理、项目级代理和工具级代理开关；
- 支持将特定 Web 请求转发至 Burp；
- DNS 和端口扫描默认不经过 HTTP 代理。

---

# 3. 完整用户流程

## 3.1 首次启动

1. 用户运行 `docker compose up -d` 或本地启动命令。
2. 系统执行环境自检：数据库、Redis、文件目录、Docker、工具安装状态、工具版本和浏览器截图环境。
3. Web 访问地址默认是 `http://127.0.0.1:8080`。
4. CLI 运行 `scopegraph doctor` 可查看相同检查结果。
5. 缺少非必要工具时允许启动，但相关扫描阶段显示“不可用”；缺少数据库等核心组件时阻止启动。

## 3.2 创建项目

用户填写：

- 项目名称；
- 企业名称，必填；
- 已知根域名，可选；
- 已知子域、IP、CIDR、URL，可选；
- 排除域名和排除 IP，可选；
- 快速、标准、深度或自定义模式；
- 是否扫描端口；
- 是否运行 Nuclei；
- 代理设置；
- 原始文件保留策略；
- 授权确认勾选，必填。

创建项目并不立即执行主动扫描。系统先进入“企业识别与 Scope 确认”。

## 3.3 企业识别与候选根域名发现

输入企业名称后执行：

1. 企业名称规范化：去除多余空格、括号，生成简称和搜索关键词。
2. 使用公开搜索页面、已知官网线索、页面版权、隐私政策、公开备案页面、本地历史项目等寻找候选页面。
3. 提取候选根域名、页面标题、版权主体、备案号、联系电话、邮箱和来源 URL。
4. 对候选根域名计算归属分数。
5. 输出候选列表：建议确认、高概率、待审核、第三方。
6. 遇到验证码时不绕过：允许用户在浏览器中人工完成、跳过来源或手动录入结果。
7. 如果无法找到可靠根域名，要求用户至少补充一个根域名，不能继续假装成功。

候选结果示例：

| 候选根域名 | 置信度 | 证据 | 状态 |
|---|---:|---|---|
| example.com | 96 | 企业名称、版权、备案一致 | 建议确认 |
| example.cn | 82 | 官网互链、页面主体一致 | 高概率 |
| example-service.com | 58 | 品牌词相似 | 待审核 |
| example.zhaopin.com | 15 | 第三方招聘平台 | 第三方 |

## 3.4 Scope 确认

用户必须确认至少一个根域名后才能启动主动扫描。

确认 `example.com` 后，默认纳入：

- `example.com`；
- `*.example.com`。

用户可添加排除项：

- `payment.example.com`；
- `supplier.example.com`；
- 指定 IP 或 CIDR。

关联公司深度：

- 0 级：仅当前企业，默认；
- 1 级：全资子公司；
- 2 级：控股公司和主要品牌；
- 3 级：其他关联主体。

关联主体默认只发现和展示，不自动扫描，除非用户明确加入 Scope。

## 3.5 扫描计划预览

启动前显示：

- 已确认根域名；
- 域名和 IP Scope；
- 排除项；
- 将运行的工具和阶段；
- 端口范围；
- 并发和速率；
- 爬虫深度和 URL 上限；
- Nuclei 模板组；
- CDN、第三方和未知 IP 策略；
- 预估目标数量和请求规模。

全端口扫描、完全 Nuclei 扫描和高风险模板必须二次确认。

## 3.6 自动扫描

扫描按照任务图运行：

```text
种子与根域名
    -> 被动子域发现
    -> DNS 小/大字典爆破
    -> 域名变体与递归验证
    -> DNS 记录和 CNAME 关系
    -> Scope 与归属判断
    -> IP 分类
    -> 端口发现
    -> 服务识别
    -> HTTP/HTTPS 探测
    -> 截图与技术栈
    -> TLS、CDN、WAF
    -> Web 爬取和 JS 端点发现
    -> 备案与主体提取
    -> 低风险安全检查
    -> 资产归并与覆盖评估
```

所有新资产都要经过：

```text
规范化 -> 查重 -> Scope 判断 -> 归属评分 -> 决定是否派生任务
```

## 3.7 审核和结果查看

扫描进行中可实时查看进度。结束后用户重点查看：

- 项目总览；
- 域名资产；
- IP 和端口；
- Web 网站截图墙；
- 网站详情；
- 备案与主体；
- 待审核资产；
- 安全发现；
- 扫描日志；
- 历史扫描对比。

## 3.8 导出和复扫

用户可导出确认资产、高概率资产或全部结果。后续手动重新扫描同一项目，系统保留所有历史并生成差异：新增、失效、IP 变化、端口变化、证书变化、备案变化和安全发现变化。

---

# 4. 用户最终看到的输出

## 4.1 项目总览

首页只放核心信息：

- 发现域名数量；
- 有效域名数量；
- IP 数量；
- 存活网站数量；
- 开放端口数量；
- ICP 备案记录数量；
- 确认资产数量；
- 高概率资产数量；
- 待审核资产数量；
- 第三方资产数量；
- 新增资产数量；
- 安全发现数量；
- 当前扫描进度；
- 任务执行完成度；
- 攻击面覆盖置信度；
- 未覆盖和待处理盲区。

## 4.2 域名资产表

字段至少包括：

- 域名；
- 根域名；
- DNS 状态；
- A/AAAA；
- CNAME；
- 发现来源；
- 首次和最后发现时间；
- Scope 状态；
- 归属状态和分数；
- 是否存在 Web；
- 是否有安全发现；
- 本轮是否新增。

## 4.3 IP 与端口页面

字段至少包括：

- IP；
- IP 类型；
- 关联域名；
- 开放端口；
- 服务和版本；
- 是否允许端口扫描；
- 分类依据；
- 首次和最后发现时间。

## 4.4 网站页面

支持表格和截图卡片切换。卡片至少显示：

- 页面截图；
- URL；
- 标题；
- 状态码；
- IP 和端口；
- 技术栈；
- CDN/WAF；
- 备案状态；
- 归属状态；
- 安全发现数量。

## 4.5 网站详情

分区展示：

1. 基础信息：URL、标题、状态码、跳转链、响应时间、内容类型。
2. DNS 和网络：域名、根域、A/AAAA、CNAME、IP 类型、端口和服务。
3. Web 特征：服务器、技术栈、响应头、favicon hash、页面 hash。
4. TLS：证书主体、签发者、有效期、SAN、错误。
5. CDN/WAF：识别结果、证据和置信度。
6. 备案：页面备案、根域关联备案、备案主体、公安备案、提取来源、核验状态。
7. 归属：总分、结论和每条加减分证据。
8. 安全发现：风险、严重性、证据、状态和原始工具输出。
9. 历史：首次发现、最后发现、历次变化。
10. 原始证据：折叠显示工具 JSON、XML、日志和截图路径。

## 4.6 备案展示原则

不是每个网站都有独立备案号。每个 Web 资产保留备案字段，但状态必须区分：

- `PAGE_DIRECT`：当前页面直接提取；
- `ROOT_DOMAIN_INFERRED`：当前页面未显示，但根域名存在备案；
- `SUBJECT_MATCH`：备案主体与企业一致；
- `RELATED_SUBJECT`：母公司、子公司或运营主体；
- `SUBJECT_CONFLICT`：主体明显冲突；
- `NOT_FOUND`：没有发现；
- `NOT_APPLICABLE`：境外或纯 IP 服务等可能不适用；
- `PENDING_MANUAL_VERIFY`：待人工核验；
- `HISTORICAL`：历史记录，当前状态未知。

推断信息和直接证据必须分开保存和展示。

---

# 5. 扫描模式与默认参数

默认参数必须可在高级模式修改。第一版采用保守设置，并允许后续通过配置文件调整。

## 5.1 快速模式

适用于初步摸底：

- Subfinder 无强制凭证数据源；
- 小字典 DNS 爆破；
- 一轮变体或不启用 AlterX；
- 常见 Web 端口；
- 基础 HTTP 探测；
- 技术栈、TLS、CDN/WAF 和备案提取；
- 不进行深度爬取；
- Nuclei 仅信息型和低风险模板。

建议默认值：

```yaml
quick:
  dns_wordlist: small
  domain_recursion_rounds: 1
  alterx_rounds: 0
  ports: [80, 443, 8080, 8443, 8000, 8888, 3000, 5000]
  http_concurrency: 30
  http_rate_limit_per_second: 50
  crawler_enabled: false
  crawler_depth: 1
  crawler_max_urls_per_site: 200
  screenshot_enabled: true
  nuclei_profile: safe-info
```

## 5.2 标准模式

默认推荐模式：

- Subfinder；
- 小字典 DNS 爆破；
- 一轮 AlterX；
- Top 100 TCP 端口；
- httpx 完整基础字段和截图；
- Katana 基础爬取；
- 备案和归属分析；
- Nuclei 低风险模板。

```yaml
standard:
  dns_wordlist: small
  domain_recursion_rounds: 2
  alterx_rounds: 1
  ports_profile: top-100
  http_concurrency: 50
  http_rate_limit_per_second: 100
  crawler_enabled: true
  crawler_depth: 3
  crawler_max_urls_per_site: 2000
  crawler_max_duration_minutes: 10
  screenshot_enabled: true
  nuclei_profile: safe
```

## 5.3 深度模式

适用于授权明确且目标规模可控的项目：

- Subfinder + Amass；
- 大字典；
- 多轮 AlterX；
- Top 1000 TCP 端口；
- gau、waybackurls 历史 URL；
- 深度 Katana 和 JavaScript 分析；
- 更多经过审核的 Nuclei 模板。

```yaml
deep:
  dns_wordlist: large
  domain_recursion_rounds: 3
  alterx_rounds: 3
  ports_profile: top-1000
  http_concurrency: 75
  http_rate_limit_per_second: 150
  crawler_enabled: true
  crawler_depth: 5
  crawler_max_urls_per_site: 10000
  crawler_max_duration_minutes: 30
  historical_urls_enabled: true
  screenshot_enabled: true
  nuclei_profile: reviewed
```

## 5.4 自定义模式

允许控制：

- 工具开关；
- 字典路径和规模；
- 变体轮数和递归轮数；
- DNS 解析器；
- 端口列表和扫描方式；
- 并发、速率、超时和重试；
- 是否截图；
- 爬虫深度、时长和 URL 上限；
- Nuclei 模板组；
- 代理；
- 文件保留时间。

禁止用户直接提交任意 Shell 命令。自定义值必须映射到平台白名单参数。

---

# 6. 工具集成清单

## 6.1 第一版核心工具

| 工具 | 阶段 | 输入 | 标准输出 | 备注 |
|---|---|---|---|---|
| Subfinder | 被动子域发现 | 根域名 | DomainObservation | 无凭证源默认启用，缺少 Token 的源跳过 |
| AlterX | 域名变体 | 已验证子域 | CandidateDomain | 只生成候选，必须 DNS 验证 |
| PureDNS | DNS 爆破与过滤 | 根域、字典 | ValidatedDomain | 使用 MassDNS 作为底层依赖 |
| MassDNS | 高速解析 | 候选域名 | RawDNSResult | 不直接暴露为业务插件 |
| dnsx | DNS 记录采集 | 域名 | DNSRecordObservation | A、AAAA、CNAME、MX、NS、TXT、SOA、PTR |
| Naabu | 快速端口发现 | IP/Host | PortObservation | 根据 IP 类型和 Scope 决定是否运行 |
| Nmap | 服务确认 | IP + 已知端口 | ServiceObservation | 只扫描 Naabu 发现端口，默认不用高风险 NSE |
| httpx | Web 探测 | Host/URL | WebsiteObservation | 状态、标题、技术、TLS、CDN/WAF、截图等 |
| Katana | Web 爬取 | Scope 内 URL | EndpointObservation | 允许 JS，不提交表单和业务 POST |
| Nuclei | 安全检查 | URL/Host | FindingObservation | 默认安全模板白名单 |

## 6.2 深度模式可选工具

- Amass：深度资产关系和主动/被动枚举；
- gau：历史 URL；
- waybackurls：Wayback 历史 URL。

## 6.3 不作为默认依赖

- FOFA、Shodan、Censys 等需要商业凭证的平台；
- 功能与 httpx 高度重叠的 WhatWeb、gowitness 等，后续有明确需求再接入；
- 高风险 PoC 聚合工具不进入默认链路。

---

# 7. 核心功能模块规格

## 7.1 项目管理

必须支持：

- 创建、编辑、归档和删除项目；
- 项目名称和企业名称；
- 已知种子资产导入；
- Scope 和排除规则；
- 扫描模式与参数快照；
- 代理和保留策略；
- 授权确认记录；
- 项目磁盘占用统计。

删除项目时默认软删除，并要求二次确认。永久删除时清理数据库、截图、原始文件和日志。

## 7.2 企业实体与候选根域名发现

输入：企业名称、简称、可选已知域名。  
输出：候选根域名、候选主体、来源、证据和分数。

实现规则：

- 搜索数据采集作为可插拔 Source Adapter；
- 解析公开网页时限制页面大小、超时和重定向；
- 域名提取后使用公共后缀规则确定 registrable root domain；
- 第三方平台域名不得因页面包含企业名称自动加入 Scope；
- 所有候选根域必须可被用户确认、排除和补充；
- 搜索或备案查询失败时要显示来源失败原因。

## 7.3 Scope 引擎

支持规则类型：

- 精确域名；
- 根域及所有子域；
- 精确 IP；
- CIDR；
- 精确 URL；
- 排除域名/IP/URL。

判定优先级：

1. 明确排除规则最高；
2. 明确 Scope；
3. 第三方和 CDN 策略；
4. 归属评分；
5. 未知资产进入待审核。

所有主动任务创建前必须调用 Scope 引擎。任务执行器再次校验，形成双重保护。

## 7.4 资产导入和规范化

支持 TXT、CSV、JSON 和 Excel 导入。资产类型：

- company；
- domain；
- ip；
- cidr；
- url；
- service；
- certificate；
- icp_record。

规范化规则：

- 域名转小写，移除末尾点，Unicode 转 Punycode；
- IP 使用标准格式，IPv6 规范压缩；
- URL 去 fragment，规范 scheme、host、默认端口和路径；
- 保留 HTTP 与 HTTPS 两个入口，但通过跳转和站点聚类建立关系；
- 所有资产生成稳定的 `normalized_key` 用于唯一索引。

## 7.5 子域名发现

流程：

1. Subfinder 被动发现；
2. 基础字典生成候选；
3. PureDNS/MassDNS 验证并过滤泛解析；
4. AlterX 对已验证名称生成变体；
5. 再次 DNS 验证；
6. 递归到配置上限；
7. 保存每个发现来源和原始证据。

必须防止：

- 泛解析导致海量假资产；
- 同一资产重复派生任务；
- 无限变体循环；
- 超过项目资产上限后继续扩张。

## 7.6 DNS 分析

采集 A、AAAA、CNAME、MX、NS、TXT、SOA、PTR。支持：

- CNAME 链追踪；
- 解析超时重试；
- 多解析器交叉验证；
- DNS 结果缓存；
- 泛解析检测；
- 第三方 SaaS CNAME 识别；
- 可能的 DNS 接管候选，只作为待验证发现；
- DNS 历史由后续可选数据源提供。

## 7.7 IP 分类和端口策略

IP 类型及默认行为：

| IP 类型 | 默认行为 |
|---|---|
| 企业自有 IP | 允许按用户选择执行端口扫描 |
| 普通云服务器 IP | 扫描与关联域名相关的端口或所选端口配置 |
| 共享托管 IP | 只探测已知 Web 端口 |
| CDN/WAF 节点 | 默认不端口扫描，只保存域名级 Web 结果 |
| 未知 IP | 轻量 HTTP 探测，不自动全端口 |

IP 分类第一版允许基于：CNAME 规则、httpx/工具识别、已知 CDN 指纹、本地规则和用户人工标记。不得仅凭解析关系声称 IP 归企业所有。

端口扫描必须可在项目设置中关闭。全端口扫描必须二次确认。

## 7.8 服务识别

Naabu 先发现端口，Nmap 只对发现端口执行服务识别。默认：

- 不对所有 IP 重新大范围扫描；
- 不启用侵入性 NSE；
- 保存 Nmap XML 原始结果；
- 标准化服务名、产品、版本和 TLS 标记。

## 7.9 Web 探测和截图

每个 WebsiteObservation 至少包含：

- 输入 URL；
- 最终 URL 和跳转链；
- status code；
- title；
- content type 和 content length；
- response time；
- IP、port、CNAME；
- server header；
- technologies；
- CDN/WAF；
- TLS 摘要；
- favicon hash；
- body hash；
- screenshot path；
- error 信息。

截图只对存活的 HTML 页面执行。浏览器必须：禁用下载、限制资源和时间、隔离进程、阻止弹窗造成死循环。

## 7.10 Web 爬取和端点发现

Katana 默认：

- 允许执行 JavaScript；
- 只访问 Scope 内地址；
- 不自动提交表单；
- 不发送业务 POST；
- 不携带 Cookie 或登录态；
- 限制深度、时长、URL 数量和请求速率；
- 外部链接只记录，不主动访问。

发现内容包括：URL、JS、XHR/fetch、WebSocket、robots.txt、sitemap.xml、API 路径和新域名。

发现新根域名时进入待审核；同根子域通过 Scope 规则后可进入 DNS 队列。

## 7.11 备案和主体提取

自研模块需要从以下页面和内容提取：

- 首页及页脚；
- 关于我们；
- 联系我们；
- 隐私政策；
- 用户协议；
- HTML 源码和 meta；
- robots/sitemap 中的相关页面。

提取字段：

- ICP 备案号；
- 公安备案号；
- 企业名称；
- 版权主体；
- 网站名称；
- 备案链接；
- 联系邮箱、电话和地址；
- 来源 URL 和原文片段。

备案号需要规范化。每条备案记录单独保存，并与多个网站建立多对多关系。自动提取不能标为官方确认。

## 7.12 资产归属评分

第一版采用规则评分，分数可配置。

建议初始规则：

| 证据 | 分值 |
|---|---:|
| 属于用户确认的根域名 | +50 |
| 备案主体与目标企业完全一致 | +40 |
| 页面版权主体完全一致 | +25 |
| 隐私政策运营主体一致 | +25 |
| 从确认官网直接链接 | +20 |
| TLS SAN 与确认域名关联 | +15 |
| 企业或品牌名称高度匹配 | +10 |
| 多个独立工具共同发现 | +5 |
| 仅相同 IP | +2 |
| CNAME 指向明确第三方平台 | -30 |
| 备案主体明显不一致 | -40 |
| 页面主体明确属于其他公司 | -50 |
| CDN 或共享托管 IP | -20 |
| 仅搜索关键词命中 | -10 |

等级：

- 90 及以上：确认资产；
- 70-89：高概率资产；
- 40-69：待人工审核；
- 1-39：弱关联，只记录；
- 0 及以下：第三方或排除。

强制要求：保存每一条评分事件，不能只保存总分。用户人工确认可覆盖自动结论，但必须保留审计记录。

## 7.13 资产去重和站点聚类

去重不等于删除原始入口。

域名唯一键：规范化 FQDN。  
IP 唯一键：规范化 IP。  
URL 唯一键：scheme + host + effective port + normalized path + 可配置 query。  
服务唯一键：IP/host + port + protocol。

站点聚类可使用：

- 最终跳转 URL；
- favicon hash；
- body hash；
- title；
- TLS 证书；
- JS/CSS 资源；
- 页面截图感知 hash，后续增强。

聚类只生成 `site_cluster` 关系，不合并删除 URL。

## 7.14 安全发现

Nuclei 默认模板策略：

允许：

- technologies；
- exposures；
- misconfiguration；
- ssl；
- 经人工审核的低风险 CVE。

默认禁止：

- dos；
- destructive；
- fuzz；
- 文件上传；
- 数据修改；
- 命令执行验证；
- 大规模默认口令。

Finding 状态：

- UNVERIFIED；
- POTENTIAL；
- REPRODUCIBLE；
- MANUALLY_VERIFIED；
- FALSE_POSITIVE；
- ACCEPTED_RISK。

每项保存模板 ID、工具版本、目标、证据、严重性、首次和最后发现时间、原始结果路径。

## 7.15 待审核中心

集中显示：

- 候选新根域名；
- 中低置信度资产；
- 备案主体冲突；
- 第三方 CNAME；
- 共享或未知 IP；
- Scope 外发现；
- Nuclei 疑似结果。

支持批量：确认、加入 Scope、排除、标记第三方、暂不处理。任何操作写入 AuditLog。

## 7.16 历史扫描和差异

每次扫描生成独立 `scan_run`。结构化数据永久保留。支持比较任意两次：

- 新增和失效域名；
- DNS/IP 变化；
- 新增和关闭端口；
- 网站上线/下线；
- 标题和技术栈变化；
- 证书变化；
- 备案变化；
- 新增和消失安全发现。

不得用物理删除表达“资产消失”，应保存观察时间和活跃状态。

## 7.17 导出

第一版：Excel、CSV、JSON、HTML、Markdown。

Excel 至少包含工作表：

- 项目总览；
- 根域名；
- 子域名；
- IP 资产；
- 端口服务；
- Web 网站；
- 备案信息；
- 第三方服务；
- 待审核资产；
- 安全发现；
- 扫描历史。

导出范围可选：仅确认资产、确认+高概率、全部候选、仅存活网站、仅安全发现。

---

# 8. 任务编排和状态机

## 8.1 总体 DAG

```text
enterprise_discovery
  -> root_domain_review
  -> passive_subdomain
  -> dns_bruteforce
  -> permutation
  -> dns_enrichment
  -> scope_and_ownership
  -> ip_classification
  -> port_discovery
  -> service_fingerprint
  -> http_probe
  -> screenshot
  -> web_crawl
  -> icp_extraction
  -> safe_nuclei
  -> final_reconciliation
  -> coverage_assessment
  -> report_ready
```

部分节点可根据扫描配置跳过。

## 8.2 任务状态

- PENDING；
- QUEUED；
- RUNNING；
- PAUSED；
- PARTIAL_SUCCESS；
- SUCCESS；
- FAILED；
- TIMEOUT；
- CANCELLED；
- SKIPPED。

## 8.3 失败和重试

默认规则：

- 工具超时：自动重试 1 次；
- DNS 失败：更换解析器后重试；
- 单个资产失败：记录错误，不阻塞批次；
- 工具不存在：任务 SKIPPED，并给安装提示；
- 输出解析失败：保存原始文件，任务 PARTIAL_SUCCESS；
- Worker 异常：未完成任务重新进入队列；
- 用户取消：终止子进程，保留已经产生的数据；
- 重试必须使用幂等键避免重复结果。

## 8.4 反馈循环

触发规则：

- TLS SAN 新域名 -> Scope 判断 -> DNS 队列；
- Katana/JS 新域名 -> 同根自动审核，新根进入待审核；
- Nmap 发现 HTTP 服务 -> httpx 队列；
- 页面跳转新域名 -> 第三方/关联判定；
- 新确认根域 -> 新一轮子域发现。

终止条件：

- 达到扫描模式递归轮数；
- 连续一轮没有新增有效根域；
- 新增有效子域低于阈值；
- 达到项目最大资产数量；
- 用户取消。

---

# 9. 系统架构

## 9.1 推荐技术栈

- Frontend：Next.js + TypeScript；
- UI：Ant Design 或同等级组件库；
- Backend：FastAPI + Python；
- ORM：SQLAlchemy 2.x；
- Migration：Alembic；
- Queue：Redis + Dramatiq 或 Celery；
- Database：PostgreSQL；
- File Storage：本地目录，预留 MinIO 适配器；
- Tool Runtime：Docker，支持宿主机工具适配；
- Screenshot：优先复用 httpx，必要时 Playwright；
- Deployment：Docker Compose；
- Tests：pytest、Playwright 前端 E2E、Vitest/Jest。

## 9.2 逻辑架构

```text
Web UI -----------\
                   -> FastAPI -> PostgreSQL
CLI --------------/      |          |
                          |          -> structured assets/history
                          -> Redis Queue -> Worker -> Tool Adapters
                                              |
                                              -> raw files/screenshots/logs
```

## 9.3 代码目录建议

```text
scopegraph/
├── apps/
│   ├── api/
│   ├── worker/
│   ├── cli/
│   └── web/
├── scopegraph/
│   ├── domain/
│   ├── application/
│   ├── infrastructure/
│   ├── adapters/
│   │   ├── tools/
│   │   ├── search_sources/
│   │   ├── storage/
│   │   └── reports/
│   ├── workflows/
│   ├── normalizers/
│   ├── scoring/
│   ├── scope_engine/
│   └── schemas/
├── migrations/
├── configs/
│   ├── scan_profiles/
│   ├── dictionaries/
│   ├── nuclei_profiles/
│   ├── cdn_rules/
│   └── third_party_rules/
├── docker/
├── tests/
│   ├── unit/
│   ├── integration/
│   ├── fixtures/
│   └── e2e/
├── docs/
├── docker-compose.yml
└── README.md
```

---

# 10. 插件和工具适配器规范

## 10.1 适配器职责

每个适配器必须实现：

- 工具存在性检查；
- 版本读取；
- 版本兼容判断；
- 输入验证；
- 参数白名单映射；
- 命令构建；
- 进程执行；
- 超时和取消；
- 原始输出保存；
- 结构化解析；
- 标准化 Observation 输出；
- 错误分类。

## 10.2 Manifest 示例

```yaml
name: subfinder
category: domain_discovery
execution_modes: [docker, host]
requires_root: false
requires_credentials: false
input_types: [root_domain]
output_types: [domain_observation]
preferred_output: jsonl
version_command: [subfinder, -version]
timeout_seconds: 1800
supported_versions:
  minimum: configurable
```

## 10.3 统一 Observation

所有工具先输出统一观察对象，再由业务服务写入资产、关系和证据。

```json
{
  "project_id": "uuid",
  "scan_run_id": "uuid",
  "source_tool": "dnsx",
  "source_version": "version-string",
  "observed_at": "ISO-8601",
  "subject": {"type": "domain", "value": "oa.example.com"},
  "predicate": "RESOLVES_TO",
  "object": {"type": "ip", "value": "192.0.2.10"},
  "attributes": {"record_type": "A", "ttl": 300},
  "raw_artifact_path": "...",
  "confidence": 1.0
}
```

---

# 11. 数据模型

建议采用统一 Asset + 专项详情表。以下是最低要求。

## 11.1 核心表

### projects

- id；
- name；
- company_name；
- company_normalized_name；
- status；
- default_scan_profile；
- authorization_confirmed_at；
- proxy_config_encrypted；
- retention_policy；
- created_at、updated_at、deleted_at。

### scope_rules

- id；
- project_id；
- rule_type：DOMAIN、ROOT_DOMAIN、IP、CIDR、URL；
- value；
- action：INCLUDE、EXCLUDE；
- source：USER、AUTO_CONFIRMED；
- created_at。

### assets

- id；
- project_id；
- asset_type；
- normalized_value；
- display_value；
- scope_status；
- ownership_status；
- confidence_score；
- first_seen_at；
- last_seen_at；
- is_active；
- metadata JSONB；
- unique(project_id, asset_type, normalized_value)。

### asset_relations

- id；
- project_id；
- source_asset_id；
- target_asset_id；
- relation_type；
- confidence；
- first_seen_at；
- last_seen_at；
- evidence_count；
- unique(project_id, source, target, relation_type)。

关系类型至少包括：

- HAS_SUBDOMAIN；
- RESOLVES_TO；
- CNAME_TO；
- HOSTS_SERVICE；
- SERVES_WEBSITE；
- REDIRECTS_TO；
- PRESENTS_CERTIFICATE；
- HAS_ICP_RECORD；
- OFFICIAL_LINK_TO；
- DISCOVERED_FROM；
- THIRD_PARTY_HOSTED_BY；
- CLUSTERED_WITH。

### observations

- id；
- project_id；
- scan_run_id；
- source_tool；
- source_version；
- subject_type/value；
- predicate；
- object_type/value；
- attributes JSONB；
- raw_artifact_path；
- observed_at；
- observation_hash unique。

### evidence

- id；
- project_id；
- asset_id；
- evidence_type；
- value；
- score_delta；
- source_tool；
- source_url；
- source_observation_id；
- observed_at；
- is_manual；
- metadata JSONB。

### scan_runs

- id；
- project_id；
- profile；
- config_snapshot JSONB；
- status；
- progress；
- started_at；
- finished_at；
- coverage_score；
- coverage_level；
- summary JSONB。

### scan_jobs

- id；
- scan_run_id；
- job_type；
- adapter_name；
- input_ref；
- idempotency_key；
- status；
- attempt；
- timeout_seconds；
- started_at；
- finished_at；
- stdout_path；
- stderr_path；
- error_code；
- error_message。

## 11.2 专项表

- dns_records；
- ip_details；
- ports；
- services；
- websites；
- web_snapshots；
- certificates；
- technologies；
- endpoints；
- icp_records；
- website_icp_links；
- findings；
- review_actions；
- audit_logs；
- file_artifacts；
- tool_installations；
- tool_compatibility_rules。

## 11.3 状态枚举

Scope：

- IN_SCOPE；
- OUT_OF_SCOPE；
- EXCLUDED；
- PENDING_REVIEW；
- THIRD_PARTY；
- CDN_SHARED；
- UNKNOWN。

归属：

- CONFIRMED；
- HIGH_CONFIDENCE；
- PENDING_REVIEW；
- WEAK_RELATION；
- THIRD_PARTY；
- REJECTED。

---

# 12. REST API 设计

API 使用 `/api/v1` 前缀，JSON 响应，统一分页和错误格式。

## 12.1 项目

- `POST /projects`；
- `GET /projects`；
- `GET /projects/{id}`；
- `PATCH /projects/{id}`；
- `DELETE /projects/{id}`；
- `GET /projects/{id}/summary`。

## 12.2 企业识别和 Scope

- `POST /projects/{id}/enterprise-discovery`；
- `GET /projects/{id}/candidate-root-domains`；
- `POST /projects/{id}/candidate-root-domains/{candidate_id}/confirm`；
- `POST /projects/{id}/candidate-root-domains/{candidate_id}/reject`；
- `POST /projects/{id}/scope-rules`；
- `GET /projects/{id}/scope-rules`；
- `DELETE /projects/{id}/scope-rules/{rule_id}`；
- `POST /projects/{id}/scope/check`。

## 12.3 扫描

- `POST /projects/{id}/scan-runs`；
- `GET /scan-runs/{id}`；
- `POST /scan-runs/{id}/pause`；
- `POST /scan-runs/{id}/resume`；
- `POST /scan-runs/{id}/cancel`；
- `POST /scan-jobs/{id}/retry`；
- `GET /scan-runs/{id}/jobs`；
- `GET /scan-runs/{id}/events`，支持 SSE 或 WebSocket。

## 12.4 资产和详情

- `GET /projects/{id}/assets`；
- `GET /assets/{id}`；
- `GET /projects/{id}/domains`；
- `GET /projects/{id}/ips`；
- `GET /projects/{id}/websites`；
- `GET /websites/{id}`；
- `GET /projects/{id}/icp-records`；
- `GET /projects/{id}/findings`；
- `GET /projects/{id}/review-queue`。

## 12.5 审核、历史和导出

- `POST /assets/{id}/review`；
- `POST /projects/{id}/reviews/batch`；
- `GET /projects/{id}/scan-runs`；
- `GET /projects/{id}/diff?from=&to=`；
- `POST /projects/{id}/exports`；
- `GET /exports/{id}`。

## 12.6 系统设置

- `GET /system/health`；
- `GET /system/tools`；
- `POST /system/tools/{name}/check-update`；
- `POST /system/tools/{name}/update`；
- `GET/PATCH /system/settings`；
- `GET /system/storage`；
- `POST /system/storage/cleanup`。

统一错误格式：

```json
{
  "error": {
    "code": "SCOPE_VIOLATION",
    "message": "Target is outside authorized scope",
    "details": {},
    "request_id": "uuid"
  }
}
```

---

# 13. CLI 设计

CLI 名称暂定 `scopegraph`。CLI 通过本地 API 或同一应用服务工作，不复制业务逻辑。

```bash
scopegraph doctor
scopegraph project create --name "Example Test" --company "Example Company"
scopegraph project list
scopegraph enterprise discover PROJECT_ID
scopegraph root-domain list PROJECT_ID
scopegraph root-domain confirm PROJECT_ID example.com
scopegraph scope add PROJECT_ID --root-domain example.com
scopegraph scope exclude PROJECT_ID --domain payment.example.com
scopegraph scan start PROJECT_ID --profile standard
scopegraph scan start PROJECT_ID --profile custom --config custom.yaml
scopegraph scan status SCAN_RUN_ID
scopegraph scan cancel SCAN_RUN_ID
scopegraph assets list PROJECT_ID --type website --status confirmed
scopegraph review list PROJECT_ID
scopegraph review confirm ASSET_ID
scopegraph diff PROJECT_ID --from RUN_A --to RUN_B
scopegraph export PROJECT_ID --format xlsx --scope confirmed-and-high
```

CLI 默认支持 `--json`，便于其他 Agent 和脚本消费。

---

# 14. Web 信息架构

## 14.1 页面

1. 项目列表；
2. 新建项目向导；
3. 企业识别和根域确认；
4. 扫描计划预览；
5. 项目总览；
6. 资产列表；
7. IP/端口；
8. 网站截图墙/表格；
9. 网站详情；
10. 备案信息；
11. 待审核中心；
12. 安全发现；
13. 扫描任务中心；
14. 历史和差异；
15. 导出中心；
16. 系统设置和工具管理；
17. 磁盘占用和清理。

## 14.2 交互原则

- 普通模式隐藏复杂参数，高级模式展开；
- 所有高风险开关需要明显警示和二次确认；
- 列表支持搜索、分页、排序、筛选和批量操作；
- 原始工具数据默认折叠；
- 页面不能把“任务 100%”写成“攻击面 100%”；
- 待审核数量始终在项目导航中可见；
- 失败阶段必须显示原因和重试入口。

---

# 15. 安全设计

## 15.1 命令执行安全

- 使用 `subprocess` 数组参数，不使用 Shell；
- 参数由 Pydantic/Schema 验证；
- 端口、域名、路径、并发、速率使用白名单和上限；
- 工具容器限制 CPU、内存、PID 和文件系统权限；
- 每个任务设置超时；
- 用户取消时终止完整进程树；
- 原始文件路径由系统生成，防止目录穿越。

## 15.2 Scope 安全

- 任务创建和执行前双重校验；
- 排除规则优先；
- 第三方真实域名不因 CNAME 被自动加入；
- CDN 节点不扩展端口扫描；
- 外部链接只记录；
- 用户人工加入 Scope 必须记录审计。

## 15.3 Web 采集安全

- 限制最大响应体；
- 限制重定向次数；
- 防止本地服务和 Docker 管理接口被错误访问；
- 对私网 IP 第一版默认阻止，除非后续内网模式明确启用；
- 截图浏览器禁止下载、文件访问和持久化 Cookie；
- 不自动提交表单和业务请求。

## 15.4 认证和数据

- 监听 127.0.0.1 时可关闭登录；
- 绑定非回环地址时强制设置密码；
- 密码使用强哈希；
- 代理凭证和敏感配置加密保存；
- 审计日志不可由普通清理任务删除；
- 导出文件明确标记项目和生成时间。

---

# 16. 文件、日志和保留策略

## 16.1 文件目录

```text
data/
├── projects/{project_id}/
│   ├── scans/{scan_run_id}/
│   │   ├── raw/{tool}/
│   │   ├── logs/
│   │   ├── screenshots/
│   │   └── exports/
│   └── attachments/
└── system/
```

## 16.2 保留策略

结构化数据库结果永久保存，除非项目被永久删除。原始文件支持：

- 永久；
- 30 天；
- 90 天；
- 手动清理。

系统显示数据库、截图、原始输出、日志和导出文件的占用。

## 16.3 日志

三类日志：

- 系统日志；
- 扫描任务日志；
- 用户审计日志。

日志中不得记录明文代理密码、Cookie 或敏感 Token。

---

# 17. 覆盖评估

攻击面覆盖分数不代表真实资产发现率，只表示流程覆盖程度。

评分因素可包括：

- 是否确认官方根域；
- 是否完成备案查询；
- 是否检查品牌和关联主体；
- 是否运行 Subfinder；
- 是否运行 DNS 爆破；
- 是否分析 TLS/SAN；
- 是否完成 Web 和 JS 爬取；
- 是否运行历史 URL；
- 是否完成多轮反馈；
- 是否处理高置信度待审核根域。

展示：低、中等、较高、高，并列出盲区，例如：

- 子公司资产未纳入；
- 3 个候选根域待审核；
- 搜索来源因验证码跳过；
- CDN 节点未端口扫描；
- 内网和分裂 DNS 未覆盖。

---

# 18. 分阶段开发计划

## 阶段 0：仓库、基础设施和工程规范

### 目标

建立可运行的空系统和开发基础。

### 任务

1. 创建 monorepo 目录；
2. FastAPI、PostgreSQL、Redis、Worker、CLI、Next.js 最小服务；
3. Docker Compose；
4. 配置加载、日志、错误格式、数据库迁移；
5. `/health` 和 `scopegraph doctor`；
6. CI：lint、type check、unit test；
7. 编写 README 启动说明。

### 验收

- `docker compose up -d` 可启动；
- Web、API、Worker、数据库、Redis 健康；
- CLI doctor 正确显示状态；
- CI 全部通过。

## 阶段 1：项目、Scope 和资产核心

### 任务

1. Projects、ScopeRule、Asset、Relation、Observation、Evidence 表；
2. 项目 CRUD；
3. Scope 引擎及单元测试；
4. 资产规范化和唯一键；
5. TXT/CSV/JSON 初始导入；
6. Web 项目列表、新建项目和 Scope 页面；
7. CLI 项目和 Scope 命令。

### 验收

- 域名/IP/URL 规范化正确；
- 排除规则优先；
- Scope 外目标无法创建主动任务；
- 重复导入不生成重复资产。

## 阶段 2：工具框架和首条扫描链

### 任务

1. ToolAdapter 基类和 Manifest；
2. 进程执行器、取消、超时、日志和原始文件；
3. Subfinder、dnsx、httpx 适配器；
4. ScanRun、ScanJob、队列和进度；
5. Observation -> Asset/Relation 写入；
6. 最小流程：根域 -> Subfinder -> dnsx -> httpx；
7. 任务中心页面。

### 验收

- 输入授权根域可发现、解析并展示 Web；
- 单个工具失败不影响已有结果；
- 原始输出可追溯；
- 取消任务会终止子进程；
- 重试不重复入库。

## 阶段 3：DNS 爆破、端口和服务

### 任务

1. PureDNS/MassDNS、AlterX；
2. 泛解析过滤；
3. Naabu、Nmap；
4. IP 分类和扫描策略；
5. IP/端口页面；
6. 快速/标准/深度配置实现；
7. 全端口二次确认。

### 验收

- 小字典和变体能发现并验证子域；
- CDN 默认不进入端口扫描；
- Naabu 输出能正确传给 Nmap；
- 端口扫描可关闭；
- Profile 参数快照保存在 ScanRun。

## 阶段 4：网站体验、爬虫和备案

### 任务

1. 网站截图和详情页；
2. Katana 适配器；
3. 新域名反馈循环；
4. ICP/公安备案/企业主体提取器；
5. 备案记录多对多关系；
6. 网站截图墙和表格切换；
7. 第三方 CNAME 规则。

### 验收

- Katana 不访问 Scope 外 URL；
- 不提交表单和业务 POST；
- 页面备案和根域关联备案区分正确；
- 新根域进入待审核而非自动扫描；
- 截图失败不会阻塞网站入库。

## 阶段 5：企业名称发现、归属和审核

### 任务

1. 企业名称规范化；
2. 搜索/公开页面 Source Adapter 框架；
3. 候选根域名页面；
4. 归属评分和证据明细；
5. 待审核中心和批量操作；
6. 关联主体深度设置；
7. 覆盖评估。

### 验收

- 只输入企业名称可产生候选根域或明确提示失败；
- 归属分数可解释；
- 人工审核覆盖自动状态并保留审计；
- 任务完成度和覆盖置信度分开显示。

## 阶段 6：Nuclei、历史和导出

### 任务

1. Nuclei 安全模板白名单；
2. Finding 状态和详情；
3. 完全扫描二次确认；
4. 历史 ScanRun 和差异计算；
5. Excel、CSV、JSON、HTML、Markdown 导出；
6. 文件保留和磁盘清理。

### 验收

- 默认不会运行危险模板；
- Nuclei 命中显示为未验证/疑似；
- 任意两次扫描可对比；
- Excel 表结构和数据库一致；
- 清理原始文件不删除结构化历史。

## 阶段 7：兼容性、打磨和发布

### 任务

1. Windows Docker Desktop、WSL2、Kali 测试；
2. 工具版本检查和用户确认更新；
3. 代理和 Burp 转发；
4. 完整 E2E；
5. 性能测试；
6. 安全测试；
7. 安装、升级、备份和恢复文档；
8. v1.0 发布包。

### 验收

- 中型项目规模稳定运行；
- 工具升级不兼容时明确阻止并提示；
- 非回环监听强制认证；
- 所有核心用户流程 E2E 通过。

---

# 19. 测试策略

## 19.1 单元测试

必须覆盖：

- 域名、IP、URL 规范化；
- Public Suffix 根域提取；
- Scope 匹配和优先级；
- 归属评分；
- ICP 和公安备案正则；
- 工具输出解析器；
- 状态机和重试；
- 差异计算；
- 导出字段映射。

## 19.2 集成测试

使用固定 Fixture 模拟：

- Subfinder -> dnsx -> httpx；
- PureDNS -> dnsx；
- Naabu -> Nmap；
- httpx -> Katana -> 新域名反馈；
- Nuclei -> Finding；
- 页面 -> ICPRecord；
- 扫描取消和重试；
- 数据库幂等写入。

CI 不应依赖真实互联网。工具适配器需支持使用录制的原始输出 Fixture。

## 19.3 自有授权测试靶场

建立测试域：

- 正常子域；
- 泛解析；
- CNAME 到第三方；
- HTTP/HTTPS；
- 多端口 Web；
- 失效域名；
- 多虚拟主机；
- 模拟备案页脚；
- 页面无备案但根域有关联备案；
- 低风险错误配置；
- 页面和 JS 中嵌入新域名。

## 19.4 性能目标

第一版目标：

- 数千个候选域名；
- 几百个 IP；
- 数千个 Web 服务；
- 数万条端点；
- 多次历史扫描。

性能测试至少验证：

- 10,000 候选域名入库和去重；
- 1,000 有效域名的 DNS/HTTP 批处理；
- 500 个截图任务的队列稳定性；
- 100,000 Observation 的查询和归并；
- 系统重启后的任务恢复。

---

# 20. 最终验收清单

## 产品流程

- [ ] 只输入企业名称可以创建项目；
- [ ] 可以生成候选根域或明确提示用户补充；
- [ ] 可以确认、排除和补充根域；
- [ ] 可以选择四种扫描模式；
- [ ] 可以关闭端口和 Nuclei；
- [ ] 全端口和完全扫描有二次确认。

## 工具链

- [ ] Subfinder、PureDNS、dnsx、AlterX、Naabu、Nmap、httpx、Katana、Nuclei 可被独立检测和调用；
- [ ] 工具版本被记录；
- [ ] 结构化输出正确解析；
- [ ] 原始结果可追溯；
- [ ] 单工具失败不摧毁整个项目。

## Scope 和安全

- [ ] Scope 外资产不主动扫描；
- [ ] 第三方 CNAME 不扩展；
- [ ] CDN 节点默认不端口扫描；
- [ ] Katana 不提交表单和业务 POST；
- [ ] 用户输入不能造成命令注入；
- [ ] 取消任务能停止进程树。

## 数据

- [ ] 资产、关系和观察结果幂等；
- [ ] 归属结论有可解释证据；
- [ ] 页面备案和根域关联备案能区分；
- [ ] 历史扫描和差异正确；
- [ ] 文件清理不损坏结构化历史。

## Web 和 CLI

- [ ] 首页统计准确；
- [ ] 网站表格/截图切换；
- [ ] 网站详情完整；
- [ ] 待审核批量处理；
- [ ] 扫描任务显示实时进度和错误；
- [ ] CLI 支持 JSON 输出；
- [ ] Web 和 CLI 结果一致。

## 导出

- [ ] Excel、CSV、JSON、HTML、Markdown 可用；
- [ ] 导出范围可选；
- [ ] 导出数据与数据库一致；
- [ ] 结果标明生成时间和项目 Scope。

---

# 21. 明确禁止事项

开发 Agent 不得：

1. 为了“功能完整”自动扫描未经确认的企业候选域名；
2. 将一个域名解析到的共享 IP 上所有服务视为企业资产；
3. 自动绕验证码或规避网站访问控制；
4. 默认启用全部 Nuclei 模板；
5. 自动提交表单、登录、注册、删除、支付等业务请求；
6. 使用用户输入构造任意 Shell；
7. 将工具命中直接标为确认漏洞；
8. 删除原始入口来“去重”；
9. 用任务完成 100% 表示资产覆盖 100%；
10. 在没有实际证据时编造备案号、IP、端口、主体或资产数量；
11. 静默自动更新工具并假设解析器仍兼容；
12. 将 AI 输出直接用于 Scope 批准或高风险执行。

---

# 22. 后续扩展

第一版完成后可考虑：

- 内网和分裂 DNS 模式；
- 分布式扫描节点；
- 定时扫描和通知；
- 团队协作与 RBAC；
- Neo4j 或图数据库视图；
- APP/APK/小程序中的 API 资产提取；
- 代码仓库和公开文档发现；
- 本地模型或自配模型辅助分类和报告；
- Jira、飞书、企业微信集成；
- 自定义安全规则和模板审批流程；
- 资产风险优先级和人工渗透工作台。

---

# 附录 A：示例项目结果 JSON

```json
{
  "project": {
    "name": "Example Company Public Attack Surface",
    "company_name": "Example Company Ltd.",
    "scan_profile": "standard"
  },
  "summary": {
    "task_completion": 100,
    "coverage_level": "HIGHER",
    "domains_discovered": 1286,
    "domains_resolved": 742,
    "ip_count": 186,
    "website_count": 329,
    "port_count": 614,
    "icp_record_count": 7,
    "confirmed_assets": 701,
    "high_confidence_assets": 28,
    "pending_review_assets": 43,
    "third_party_assets": 96,
    "finding_count": 37
  },
  "coverage_gaps": [
    "Subsidiaries not included",
    "Three candidate root domains pending review",
    "CDN nodes were not port scanned",
    "Internal assets are outside v1 scope"
  ]
}
```

# 附录 B：Agent 每阶段交付模板

```text
阶段名称：
完成内容：
新增文件/迁移：
启动命令：
测试命令：
测试结果：
手工验收步骤：
已知问题：
安全约束验证：
下一阶段依赖：
```

# 附录 C：建议的第一条可运行纵向切片

开发 Agent 应优先完成一个非常小但完整的闭环：

```text
用户创建项目
-> 手动输入并确认 example.com
-> Subfinder 发现子域
-> dnsx 解析
-> httpx 探测
-> 数据入库
-> Web 显示域名和网站
-> CLI 可查询 JSON
-> 原始文件可追溯
```

只有这个纵向切片稳定后，再添加 DNS 爆破、端口、爬虫、备案、企业名称发现和 Nuclei。这样可避免同时调试十个工具而无法定位问题。

---

**文档结束。**
