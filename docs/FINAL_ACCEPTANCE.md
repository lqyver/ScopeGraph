# ScopeGraph v1.0 最终验收映射

> 本文记录实现阶段当时的验收快照，测试数量和运行环境属于历史证据。当前 Community Edition
> 发布候选的实时门槛与待验证项以 `PUBLIC_RELEASE_READINESS.md` 为准。

本表逐项对应开发书第 20 节。证据来自单元测试、固定 fixture E2E、Docker production build、
数据库迁移、容量基准和 Worker 重启测试，不使用真实互联网目标。

## 产品流程

| 验收项 | 结论 | 证据 |
|---|---|---|
| 仅企业名称创建项目 | 通过 | Phase 5 E2E 可创建且本地无证据时明确 `NO_CANDIDATE_ROOTS` |
| 候选生成/补充提示 | 通过 | fixture 候选与显式空结果路径 |
| 确认、排除、补充根域 | 通过 | Candidate API、批量 Review、Web、CLI、审计日志 |
| Quick/Standard/Deep/Custom | 通过 | API 闭合 Profile；Web/CLI Custom JSON；Deep 单独二次确认 |
| 关闭端口和 Nuclei | 通过 | Profile 覆盖、扫描 UI、Phase 3/6 E2E |
| 全端口/Deep 二次确认 | 通过 | Schema、CLI、Web 三层强制，缺失返回 422/CLI code 2 |

## 工具链与安全

| 验收项 | 结论 | 证据 |
|---|---|---|
| 工具独立检测和调用 | 通过 | `/system/tools` 返回 10 个 Adapter，闭合输入与版本签名 |
| 版本/结构化输出/原始追溯 | 通过 | Job 版本、Observation、Artifact 哈希和安全路径 |
| 单工具失败隔离 | 通过 | Screenshot 失败不丢 Website，Run 为部分成功 |
| Scope 外不主动扫描 | 通过 | 每阶段 worker 再检查、Phase 2 越界拒绝 |
| 第三方 CNAME/CDN 隔离 | 通过 | Phase 3/4 分类与端口阻止测试 |
| Katana 无表单/业务 POST | 通过 | 固定 FQDN/GET 策略和适配器参数断言 |
| 命令注入防护 | 通过 | Pydantic extra-forbid、argv 执行、代理/Custom 未知字段拒绝 |
| 取消停止进程树 | 通过 | SafeProcessRunner 取消与状态机测试 |
| 非回环强制认证 | 通过 | API 启动保护、恒定时间 Key 比较、Web/CLI/健康检查服务端转发 |

## 数据、Web、CLI 与导出

| 验收项 | 结论 | 证据 |
|---|---|---|
| 幂等资产/关系/Observation | 通过 | Phase 2 复扫新增资产 0、Evidence 哈希、数据库唯一约束 |
| 可解释归属 | 通过 | 版本化权重、Evidence、人工覆盖不被自动评分覆盖 |
| 备案证据区分 | 通过 | `PAGE_DIRECT` 与 `ROOT_DOMAIN_INFERRED` E2E |
| 历史差异/文件清理 | 通过 | 任意 ScanRun diff；清理后结构化记录删除数恒为 0 |
| 首页/网站/审核/进度 | 通过 | Docker UI 路由、网站墙/表格、详情、审核和 2 秒任务轮询 |
| CLI JSON 与 Web 一致 | 通过 | 二者调用同一 `/api/v1`，CLI 路由契约和真实容器 doctor |
| 五种格式与范围 | 通过 | XLSX/CSV ZIP/JSON/HTML/Markdown E2E；5 类 Scope |
| Excel 与数据库一致 | 通过 | 固定 11 表数据集；artifact-tool 逐表导入、0 公式错误、全表渲染 |
| 生成时间与项目 Scope | 通过 | 导出总览元数据及 ExportArtifact 哈希/行数 |

## 非功能验收

- 90 项 Python 单元测试、11 项 Web 测试；Ruff、mypy strict、ESLint、TypeScript 通过；
- 10k 候选、1k DNS/HTTP、500 截图计划、100k Observation 容量完成；
- Worker 停机排队、重启恢复完成；
- Windows Docker Desktop 与 Linux/amd64 容器已实测，Docker 内置工具 10/10 兼容，Chromium
  中文页面渲染通过；Kali Rolling 用户态安装、CLI、Nmap 检测已实测；独立 WSL2 Ubuntu 与
  Kali 宿主工具链仍未宣称实测。

更详细的测量值见 `PHASE_7_RELEASE.md`，部署边界见 `COMPATIBILITY.md`。
