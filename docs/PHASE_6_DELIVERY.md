# 阶段 6 交付记录

## 阶段名称

安全发现、历史差异、结构化导出和存储生命周期。

## 完成内容

- `0008_phase_six` 增加 Finding 与 ExportArtifact；
- Nuclei 固定允许 tech/exposure/misconfig/ssl，明确阻止 dos/fuzz/file-upload/default-login/
  intrusive/rce，关闭自动更新和 Interactsh；启用必须单独勾选并二次确认；
- 命中初始状态统一为 `UNVERIFIED`，人工可改为疑似、确认、误报或忽略，复扫保留人工状态；
- 任意两个同项目 ScanRun 的 domain/dns/port/website/filing/finding/observation 差异；
- XLSX、CSV ZIP、JSON、HTML、Markdown 五种导出和五类导出范围；
- XLSX 固定 11 个中文工作表，含标题样式、冻结表头、自动筛选和类型化单元格；CSV/XLSX
  均防电子表格公式注入；
- 文件哈希、大小、行数和受数据根目录约束的下载路径；
- 清理原始文件/导出必须确认，且永不删除结构化历史。

## 自动验收

Phase 6 E2E 验证危险默认关闭、缺少二次确认返回 422、Finding 人工状态、任意扫描差异、五种
格式下载、11 个工作表和清理确认。XLSX 又通过 artifact-tool 对 11 个工作表逐表导入、公式
错误扫描和渲染 QA，公式错误为 0。

## 已知边界

CSV 交付为包含 11 张同构表的 ZIP；Nuclei 结果是线索而非漏洞结论；删除结构化历史不属于
存储清理功能，需按备份/恢复文档执行数据库级维护。

