"use client";

import Link from "next/link";
import { useCallback, useEffect, useState } from "react";

import {
  AttackSurfacePage,
  apiRequest,
  errorMessage,
  ExportArtifact,
  Finding,
  FindingPage,
  Project,
  ScanJob,
  ScanDiff,
  ScanRun,
  ScanRunOverviewPage,
} from "./api";
import { AttackSurfaceOverview } from "./attack-surface-overview";
import { evidenceModeQuery, type EvidenceMode } from "./evidence-mode";
import { adapterLabel, jobIssueText, jobResultLine, scanStatusLabel } from "./scan-utils";
import { useEvidenceMode } from "./use-evidence-mode";

interface SecurityCenterProps { projectId: string; initialMode?: EvidenceMode; }

export function SecurityCenter({ projectId, initialMode = "host" }: SecurityCenterProps) {
  const [project, setProject] = useState<Project | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [runs, setRuns] = useState<ScanRun[]>([]);
  const [nucleiJobs, setNucleiJobs] = useState<ScanJob[]>([]);
  const [attackSurface, setAttackSurface] = useState<AttackSurfacePage | null>(null);
  const [fromRun, setFromRun] = useState("");
  const [toRun, setToRun] = useState("");
  const [diff, setDiff] = useState<ScanDiff | null>(null);
  const [format, setFormat] = useState<ExportArtifact["export_format"]>("xlsx");
  const [exportScope, setExportScope] = useState("confirmed-and-high");
  const [createdExport, setCreatedExport] = useState<ExportArtifact | null>(null);
  const [loading, setLoading] = useState(true);
  const [working, setWorking] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [mode, setMode] = useEvidenceMode(initialMode);
  const [findingTotal, setFindingTotal] = useState(0);

  const load = useCallback(async () => {
    try {
      const [projectData, findingData, overviewData, surfaceData] = await Promise.all([
        apiRequest<Project>(`projects/${projectId}`),
        apiRequest<FindingPage>(`projects/${projectId}/findings-page?page=1&page_size=100&execution_mode=${mode}`),
        apiRequest<ScanRunOverviewPage>(`projects/${projectId}/scan-runs-overview?page_size=20&execution_mode=${mode}`),
        apiRequest<AttackSurfacePage>(`projects/${projectId}/attack-surface?page=1&page_size=50&execution_mode=${mode}`),
      ]);
      const runItems = overviewData.items.map((item) => item.run);
      setProject(projectData); setFindings(findingData.items); setFindingTotal(findingData.total); setRuns(runItems);
      setNucleiJobs(overviewData.items.flatMap((item) => item.jobs.filter((job) => job.adapter_name === "nuclei")));
      setAttackSurface(surfaceData);
      setError(null);
      if (!fromRun && runItems[1]) setFromRun(runItems[1].id);
      if (!toRun && runItems[0]) setToRun(runItems[0].id);
    } catch (caught) { setError(errorMessage(caught)); }
    finally { setLoading(false); }
  }, [fromRun, mode, projectId, toRun]);

  useEffect(() => {
    const initial = window.setTimeout(() => void load(), 0);
    const timer = window.setInterval(() => {
      if (document.visibilityState === "visible") void load();
    }, 5000);
    return () => { window.clearTimeout(initial); window.clearInterval(timer); };
  }, [load]);

  async function compare() {
    setWorking(true); setError(null);
    try { setDiff(await apiRequest<ScanDiff>(`projects/${projectId}/diff?from=${fromRun}&to=${toRun}`)); }
    catch (caught) { setError(errorMessage(caught)); }
    finally { setWorking(false); }
  }

  async function createExport() {
    setWorking(true); setError(null);
    try {
      setCreatedExport(await apiRequest<ExportArtifact>(`projects/${projectId}/exports`, {
        method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({ export_format: format, export_scope: exportScope, execution_mode: mode }),
      }));
    } catch (caught) { setError(errorMessage(caught)); }
    finally { setWorking(false); }
  }

  async function reviewFinding(finding: Finding, status: Finding["status"]) {
    setWorking(true); setError(null);
    try {
      await apiRequest(`findings/${finding.id}/review`, {
        method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({ status, reason: "经本地管理员人工复核" }),
      });
      await load();
    } catch (caught) { setError(errorMessage(caught)); }
    finally { setWorking(false); }
  }

  if (loading) return <div className="loading-panel">正在加载安全发现与历史…</div>;
  if (!project) return <div className="error-panel">{error ?? "项目不存在"}</div>;
  const latestNuclei = nucleiJobs[0];
  const activeFindings = findings.filter((finding) => finding.is_active).length;
  const highFindings = findings.filter((finding) => ["high", "critical"].includes(finding.severity)).length;
  return <>
    <header className="security-heading"><div><p className="eyebrow">PHASE 6 / EVIDENCE & DELIVERY</p><h1>安全发现、历史与导出</h1><p>{project.name} · 工具命中不是漏洞结论，所有状态均保留人工复核轨迹。</p></div><Link className="button-secondary" href={`/projects/${projectId}/scans`}>扫描任务 →</Link></header>
    {error && <div className="enterprise-alert is-error" role="alert">{error}</div>}
    <section className="website-toolbar" aria-label="安全证据来源"><label><span>证据来源</span><select value={mode} onChange={(event) => { setMode(event.target.value as EvidenceMode); setFromRun(""); setToRun(""); setDiff(null); }}><option value="host">真实扫描结果</option><option value="fixture">演示扫描结果</option></select></label><Link className="button-secondary" href={`/projects/${projectId}/network${evidenceModeQuery(mode)}`}>对应网络证据</Link></section>
    {attackSurface ? <AttackSurfaceOverview projectId={projectId} data={attackSurface} compact mode={mode} /> : null}
    <section className="security-section"><div className="section-heading"><div><p className="section-index">01 / UNVERIFIED FINDINGS</p><h2>安全发现 {findingTotal}</h2></div></div>
      <div className="inventory-summary security-scan-health">
        <div><span>检查状态</span><strong>{latestNuclei ? scanStatusLabel(latestNuclei.status) : "未启用"}</strong></div>
        <div><span>本次仍出现</span><strong>{activeFindings}</strong></div>
        <div><span>高危 / 严重</span><strong>{highFindings}</strong></div>
        <div><span>最近检查目标</span><strong>{Number(latestNuclei?.result_summary.input_count ?? 0).toLocaleString("zh-CN")}</strong></div>
      </div>
      <div className={latestNuclei && ["FAILED", "TIMEOUT", "PARTIAL_SUCCESS"].includes(latestNuclei.status) ? "enterprise-alert is-error" : "enterprise-alert"}>
        {latestNuclei ? <><strong>{adapterLabel(latestNuclei.adapter_name)} · {scanStatusLabel(latestNuclei.status)}</strong><span>{latestNuclei.error_code === "OUTPUT_PARSE_ERROR" ? "该历史任务的输出曾被日志行误判为 JSONL 异常；已修复解析器。下一次经授权的执行会保留有效命中，并把仅含诊断日志的无命中结果标记为成功。" : jobIssueText(latestNuclei) ?? jobResultLine(latestNuclei)}</span>{latestNuclei.error_code ? <code>{latestNuclei.error_code}</code> : null}</> : <><strong>尚未运行安全模板检查</strong><span>请在 Standard 或 Deep 扫描中启用 Nuclei 并完成二次授权；普通网站探测不会自动冒充漏洞扫描。</span></>}
      </div>
      <div className="finding-grid">{findings.length ? findings.map((finding) => <article key={finding.id} className={`finding-card severity-${finding.severity}`}><header><span>{finding.severity.toUpperCase()}</span><em>{finding.status}</em></header><h3>{finding.template_name}</h3><code>{finding.template_id}</code><p>{finding.target}</p><small>{finding.is_active ? "本次仍出现" : "最近一次已消失"} · {finding.tool_version}</small><details><summary>证据与原始路径</summary><pre>{JSON.stringify(finding.evidence, null, 2)}</pre><code>{finding.raw_artifact_path}</code></details><div><button disabled={working} onClick={() => void reviewFinding(finding, "POTENTIAL")}>标记疑似</button><button disabled={working} onClick={() => void reviewFinding(finding, "FALSE_POSITIVE")}>误报</button><button disabled={working} onClick={() => void reviewFinding(finding, "ACCEPTED_RISK")}>接受风险</button></div></article>) : <div className="empty-state"><span>NO FINDINGS</span><h2>{latestNuclei?.status === "SUCCESS" ? "最近一次安全检查没有模板命中。" : latestNuclei ? "安全检查尚未完整成功。" : "尚无安全检查结果。"}</h2><p>{latestNuclei?.status === "SUCCESS" ? "这表示当前安全模板没有产生未验证命中，不代表网站不存在漏洞。" : latestNuclei ? "上方已显示工具状态与失败原因；修复后可从任务中心单独重试。" : "从任务中心启用 Nuclei 后，结果与工具异常都会明确显示在这里。"}</p></div>}</div>
    </section>
    <section className="security-section history-export-grid"><div className="history-panel"><p className="section-index">02 / SCAN DIFF</p><h2>任意两次扫描对比</h2><div className="diff-controls"><select value={fromRun} onChange={(event) => setFromRun(event.target.value)}>{runs.map((run) => <option value={run.id} key={run.id}>FROM · {run.status} · {new Date(run.created_at).toLocaleString("zh-CN")}</option>)}</select><select value={toRun} onChange={(event) => setToRun(event.target.value)}>{runs.map((run) => <option value={run.id} key={run.id}>TO · {run.status} · {new Date(run.created_at).toLocaleString("zh-CN")}</option>)}</select><button disabled={working || !fromRun || !toRun || fromRun === toRun} onClick={() => void compare()}>计算差异</button></div>{diff && <div className="diff-metrics"><strong>+{diff.counts.added}<small>新增</small></strong><strong>−{diff.counts.removed}<small>消失</small></strong><strong>~{diff.counts.changed}<small>变化</small></strong></div>}</div>
      <div className="export-panel"><p className="section-index">03 / STRUCTURED EXPORT</p><h2>五种可追溯导出</h2><select value={format} onChange={(event) => setFormat(event.target.value as typeof format)}><option value="xlsx">Excel 多工作表</option><option value="csv">CSV 工作表压缩包</option><option value="json">JSON</option><option value="html">HTML</option><option value="markdown">Markdown</option></select><select value={exportScope} onChange={(event) => setExportScope(event.target.value)}><option value="confirmed">仅确认资产</option><option value="confirmed-and-high">确认 + 高概率</option><option value="all-candidates">全部候选</option><option value="live-websites">仅存活网站</option><option value="findings-only">仅安全发现</option></select><button disabled={working} onClick={() => void createExport()}>生成导出</button>{createdExport && <div className="export-result"><strong>{createdExport.status}</strong><span>{createdExport.size_bytes ?? 0} bytes · SHA256 {createdExport.sha256?.slice(0, 16)}…</span>{createdExport.status === "SUCCESS" && <a href={`/api/backend/exports/${createdExport.id}/download`}>下载 {createdExport.export_format.toUpperCase()} →</a>}{createdExport.error_message && <p>{createdExport.error_message}</p>}</div>}</div>
    </section>
  </>;
}
