"use client";

import Link from "next/link";
import { FormEvent, useCallback, useEffect, useRef, useState } from "react";

import {
  apiRequest,
  errorMessage,
  Project,
  ScanJob,
  ScanRun,
  ScanRunOverviewPage,
  ScopeRule,
  SystemSettings,
  ToolStatus,
} from "./api";
import {
  adapterLabel,
  formatDuration,
  jobElapsed,
  jobIssueText,
  jobResultLine,
  runExecutionPresentation,
  runResultLine,
  scanStatusLabel,
} from "./scan-utils";
import { evidenceModeQuery } from "./evidence-mode";

interface ScanCenterProps {
  projectId: string;
}

const terminal = new Set(["SUCCESS", "PARTIAL_SUCCESS", "FAILED", "TIMEOUT", "CANCELLED", "SKIPPED"]);
const RUN_PAGE_SIZE = 6;

export function ScanCenter({ projectId }: ScanCenterProps) {
  const [project, setProject] = useState<Project | null>(null);
  const [runs, setRuns] = useState<ScanRun[]>([]);
  const [jobs, setJobs] = useState<Record<string, ScanJob[]>>({});
  const [scopeRules, setScopeRules] = useState<ScopeRule[]>([]);
  const [tools, setTools] = useState<ToolStatus[] | null>(null);
  const [rootDomain, setRootDomain] = useState("");
  const [mode, setMode] = useState<"fixture" | "host">("host");
  const [profile, setProfile] = useState<"quick" | "standard" | "deep" | "custom">("standard");
  const [confirmDeep, setConfirmDeep] = useState(false);
  const [customConfig, setCustomConfig] = useState(
    '{\n  "port_scan_enabled": false,\n  "ports": [80, 443],\n  "http_probe": true,\n  "screenshot_enabled": true\n}',
  );
  const [portScan, setPortScan] = useState(true);
  const [fullPort, setFullPort] = useState(false);
  const [confirmFullPort, setConfirmFullPort] = useState(false);
  const [nuclei, setNuclei] = useState(false);
  const [screenshots, setScreenshots] = useState(true);
  const [confirmNuclei, setConfirmNuclei] = useState(false);
  const [proxyUrl, setProxyUrl] = useState("");
  const [authorized, setAuthorized] = useState(false);
  const [allowActive, setAllowActive] = useState(false);
  const [creating, setCreating] = useState(false);
  const [loading, setLoading] = useState(true);
  const [lastUpdatedAt, setLastUpdatedAt] = useState<number | null>(null);
  const [now, setNow] = useState(() => Date.now());
  const [error, setError] = useState<string | null>(null);
  const [runPage, setRunPage] = useState(1);
  const [runTotal, setRunTotal] = useState(0);
  const profileInitialized = useRef(false);
  const createPanelRef = useRef<HTMLDetailsElement>(null);
  const livePanelRef = useRef<HTMLElement>(null);
  const scrollToLiveAfterCreate = useRef(false);

  const refreshRuns = useCallback(async () => {
    const overview = await apiRequest<ScanRunOverviewPage>(
      `projects/${projectId}/scan-runs-overview?page=${runPage}&page_size=${RUN_PAGE_SIZE}`,
    );
    setRuns(overview.items.map((item) => item.run));
    setJobs(Object.fromEntries(overview.items.map((item) => [item.run.id, item.jobs])));
    setRunTotal(overview.total);
    setLastUpdatedAt(Date.now());
  }, [projectId, runPage]);

  const load = useCallback(async () => {
    try {
      const [projectData, systemSettings, ruleData] = await Promise.all([
        apiRequest<Project>(`projects/${projectId}`),
        apiRequest<SystemSettings>("system/settings"),
        apiRequest<ScopeRule[]>(`projects/${projectId}/scope-rules`),
      ]);
      setProject(projectData);
      if (!profileInitialized.current) {
        setProfile(projectData.default_scan_profile);
        setPortScan(projectData.default_scan_profile !== "custom");
        profileInitialized.current = true;
      }
      setScopeRules(ruleData);
      const includedRoots = ruleData.filter(
        (rule) => rule.rule_type === "ROOT_DOMAIN" && rule.action === "INCLUDE",
      );
      setRootDomain((current) => current || includedRoots[0]?.value || "");
      setProxyUrl((current) => current || systemSettings.proxy_url || "");
      await refreshRuns();
      setError(null);
    } catch (caught) {
      setError(errorMessage(caught));
    } finally {
      setLoading(false);
    }
  }, [projectId, refreshRuns]);

  useEffect(() => {
    const initial = window.setTimeout(() => void load(), 0);
    const timer = window.setInterval(() => {
      if (runs.some((run) => !terminal.has(run.status))) {
        void refreshRuns().catch((caught) => setError(errorMessage(caught)));
      }
    }, 2000);
    return () => {
      window.clearTimeout(initial);
      window.clearInterval(timer);
    };
  }, [load, refreshRuns, runs]);

  useEffect(() => {
    const timer = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, []);

  useEffect(() => {
    if (!scrollToLiveAfterCreate.current || !runs.some((run) => !terminal.has(run.status))) return;
    scrollToLiveAfterCreate.current = false;
    const frame = window.requestAnimationFrame(() => {
      livePanelRef.current?.scrollIntoView({ block: "start", behavior: "auto" });
    });
    return () => window.cancelAnimationFrame(frame);
  }, [runs]);

  useEffect(() => {
    const initial = window.setTimeout(() => {
      void apiRequest<ToolStatus[]>("system/tools")
        .then(setTools)
        .catch((caught) => setError(errorMessage(caught)));
    }, 0);
    return () => window.clearTimeout(initial);
  }, []);

  async function createRun(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setCreating(true);
    setError(null);
    try {
      let parsedCustomConfig: Record<string, unknown> | null = null;
      if (profile === "custom") {
        const candidate: unknown = JSON.parse(customConfig);
        if (candidate === null || Array.isArray(candidate) || typeof candidate !== "object") {
          throw new Error("Custom 配置必须是 JSON 对象");
        }
        parsedCustomConfig = candidate as Record<string, unknown>;
      }
      await apiRequest<ScanRun>(`projects/${projectId}/scan-runs`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          root_domain: rootDomain,
          profile,
          execution_mode: mode,
          authorization_confirmed: authorized,
          allow_active_execution: mode === "host" && allowActive,
          port_scan_enabled: profile === "custom" ? null : portScan,
          screenshot_enabled: profile === "custom" ? null : screenshots,
          deep_confirmation: profile === "deep" && confirmDeep,
          full_port_scan: fullPort,
          full_port_confirmation: fullPort && confirmFullPort,
          nuclei_enabled: nuclei,
          nuclei_confirmation: nuclei && confirmNuclei,
          proxy_url: proxyUrl || null,
          custom_config: parsedCustomConfig,
        }),
      });
      setAuthorized(false);
      setAllowActive(false);
      setConfirmDeep(false);
      setFullPort(false);
      setConfirmFullPort(false);
      setNuclei(false);
      setConfirmNuclei(false);
      scrollToLiveAfterCreate.current = true;
      setRunPage(1);
      await refreshRuns();
      if (createPanelRef.current) createPanelRef.current.open = false;
    } catch (caught) {
      setError(errorMessage(caught));
    } finally {
      setCreating(false);
    }
  }

  async function action(runId: string, name: "pause" | "resume" | "cancel") {
    if (name === "cancel" && !window.confirm("取消任务并终止正在运行的工具进程？已产生的证据会保留。")) return;
    try {
      await apiRequest<ScanRun>(`scan-runs/${runId}/${name}`, { method: "POST" });
      await refreshRuns();
    } catch (caught) {
      setError(errorMessage(caught));
    }
  }

  async function retry(jobId: string) {
    try {
      await apiRequest<ScanJob>(`scan-jobs/${jobId}/retry`, { method: "POST" });
      await refreshRuns();
    } catch (caught) {
      setError(errorMessage(caught));
    }
  }

  if (loading) return <div className="loading-panel">正在加载任务中心…</div>;
  if (!project) return <div className="error-panel">{error ?? "项目不存在"}</div>;

  const includedRoots = scopeRules.filter(
    (rule) => rule.rule_type === "ROOT_DOMAIN" && rule.action === "INCLUDE",
  );
  const compatibleToolCount = tools?.filter((tool) => tool.compatible).length ?? 0;
  const activeRun = runs.find((run) => !terminal.has(run.status));
  const activeJobs = activeRun ? jobs[activeRun.id] ?? [] : [];
  const runningJobs = activeJobs.filter((job) => job.status === "RUNNING");
  const currentJob = runningJobs[0]
    ?? activeJobs.find((job) => ["QUEUED", "PENDING"].includes(job.status));
  const completedStages = activeJobs.filter((job) => terminal.has(job.status)).length;
  const latestRun = runs[0];
  const latestFunnel = latestRun?.summary.funnel && typeof latestRun.summary.funnel === "object"
    ? latestRun.summary.funnel as Record<string, unknown>
    : {};
  const funnelNumber = (key: string) => Number(latestFunnel[key] ?? 0);

  return (
    <>
      <section className="project-context">
        <div>
          <p className="section-index">SCAN CONTROL / DOUBLE SCOPE GATE</p>
          <h1>{project.name}</h1>
          <p>任务完成度与攻击面覆盖置信度分开呈现。</p>
        </div>
        <div className="inventory-nav"><Link className="button-secondary" href={`/projects/${projectId}/scope`}>Scope 与资产</Link><Link className="button-secondary" href={`/projects/${projectId}/websites`}>网站结果</Link><Link className="button-secondary" href={`/projects/${projectId}/network`}>IP / 端口</Link><Link className="button-secondary" href={`/projects/${projectId}/security`}>安全与导出</Link></div>
      </section>

      {activeRun ? <section ref={livePanelRef} className="live-scan-panel" aria-label="实时扫描进度">
        <header>
          <div>
            <p className="section-index">LIVE SCAN / AUTO REFRESH</p>
            <h2>{runningJobs.length > 1 ? `并行执行 ${runningJobs.length} 个阶段` : currentJob ? adapterLabel(currentJob.adapter_name) : "正在收尾扫描任务"}</h2>
            <p>{runningJobs.length > 1 ? runningJobs.map((job) => adapterLabel(job.adapter_name)).join(" · ") : currentJob ? jobResultLine(currentJob) : "正在汇总阶段结果与覆盖评估。"}</p>
          </div>
          <span className="live-indicator" aria-live="polite">实时更新 · {scanStatusLabel(activeRun.status)}</span>
        </header>
        <div className="live-scan-metrics">
          <div><span>整体完成度</span><strong>{activeRun.progress.toFixed(0)}%</strong><progress max="100" value={activeRun.progress} /></div>
          <div><span>阶段进度</span><strong>{completedStages}/{activeJobs.length}</strong><small>{runningJobs.length > 1 ? `${runningJobs.length} 个阶段并行运行` : currentJob ? currentJob.status === "RUNNING" ? `已运行 ${jobElapsed(currentJob, now)} / 上限 ${formatDuration(currentJob.timeout_seconds)}` : `等待执行 / 上限 ${formatDuration(currentJob.timeout_seconds)}` : "阶段结果汇总中"}</small></div>
          <div><span>已产生结果</span><strong>{Number(activeRun.summary.observations_created ?? 0).toLocaleString("zh-CN")}</strong><small>{Number(activeRun.summary.assets_created ?? 0).toLocaleString("zh-CN")} 项资产变化</small></div>
        </div>
        <ol className="live-stage-list">
          {activeJobs.map((job) => <li key={job.id} className={`stage-${job.status.toLowerCase()}`}>
            <span>{String(job.sequence + 1).padStart(2, "0")}</span>
            <strong>{adapterLabel(job.adapter_name)}</strong>
            <em>{scanStatusLabel(job.status)}</em>
            <small>{job.status === "RUNNING" ? jobElapsed(job, now) : jobResultLine(job)}</small>
          </li>)}
        </ol>
        <footer>页面每 2 秒通过单个聚合请求同步；{lastUpdatedAt ? `最近同步于 ${new Date(lastUpdatedAt).toLocaleTimeString("zh-CN")}` : "正在建立实时连接"}。关闭页面不会中断扫描。</footer>
      </section> : null}

      {error ? <p className="form-error global-error" role="alert">{error}</p> : null}

      <section className="coverage-panel" aria-label="开始扫描前检查">
        <div className="coverage-score">
          <span>START HERE</span>
          <strong>{(includedRoots.length ? 1 : 0) + (tools !== null && compatibleToolCount > 0 ? 1 : 0)}/2</strong>
          <small>{includedRoots.length && tools !== null && compatibleToolCount > 0 ? "READY" : "CHECK REQUIRED"}</small>
        </div>
        <div>
          <h2>{includedRoots.length && tools !== null && compatibleToolCount > 0 ? "可以开始扫描" : includedRoots.length ? "正在检查扫描工具" : "还差一个已确认根域"}</h2>
          <p>{includedRoots.length
            ? `将只允许扫描：${includedRoots.map((rule) => rule.value).join("、")}`
            : "先从企业发现页确认候选根域，或在 Scope 页面手工添加根域。"}</p>
          {!includedRoots.length ? <div className="inventory-nav"><Link className="button-primary" href={`/projects/${projectId}/enterprise`}>发现并确认根域</Link><Link className="button-secondary" href={`/projects/${projectId}/scope`}>手工配置 Scope</Link></div> : null}
        </div>
      </section>

      {!activeRun && runs[0] && terminal.has(runs[0].status) ? <section className="scope-panel latest-result-panel">
        <div>
          <p className="section-index">LATEST RESULT</p>
          <h2>最近一次扫描：{scanStatusLabel(runs[0].status)}</h2>
          <p>{runResultLine(runs[0], jobs[runs[0].id] ?? [])}</p>
        </div>
        <div className="inventory-nav">
          <Link className="button-primary" href={`/projects/${projectId}/websites${evidenceModeQuery(runs[0].config_snapshot.execution_mode)}`}>查看网站结果</Link>
          <Link className="button-secondary" href={`/projects/${projectId}/scope${evidenceModeQuery(runs[0].config_snapshot.execution_mode)}`}>查看全部资产</Link>
          <Link className="button-secondary" href={`/projects/${projectId}/network${evidenceModeQuery(runs[0].config_snapshot.execution_mode)}`}>查看网络结果</Link>
        </div>
      </section> : null}

      {!activeRun && latestRun && terminal.has(latestRun.status) ? <section className="scope-panel asset-panel" aria-label="All-in-One 资产漏斗">
        <div className="panel-heading"><div><p className="section-index">ALL-IN-ONE ASSET FUNNEL</p><h2>从原始域名到可行动攻击面</h2><p className="panel-note">每一层直接复用上一阶段的结构化结果；不是把 Subfinder 输出原样展示。</p></div><span className="guard-badge">PARALLEL DAG</span></div>
        <section className="inventory-summary">
          <div><span>Subfinder 原始子域</span><strong>{funnelNumber("subdomains_discovered").toLocaleString("zh-CN")}</strong></div>
          <div><span>DNS 验证目标</span><strong>{funnelNumber("domains_validated").toLocaleString("zh-CN")}</strong></div>
          <div><span>存活网站</span><strong>{funnelNumber("websites_alive").toLocaleString("zh-CN")}</strong></div>
          <div><span>端口候选检查</span><strong>{funnelNumber("candidate_port_checks").toLocaleString("zh-CN")}</strong></div>
          <div><span>开放端口</span><strong>{funnelNumber("open_ports").toLocaleString("zh-CN")}</strong></div>
          <div><span>网页 / 接口</span><strong>{funnelNumber("web_endpoints_discovered").toLocaleString("zh-CN")}</strong></div>
          <div><span>安全命中待核验</span><strong>{funnelNumber("unverified_security_hits").toLocaleString("zh-CN")}</strong></div>
          <div><span>并行节省</span><strong>{formatDuration(Number(latestRun.summary.parallel_time_saved_seconds ?? 0))}</strong></div>
        </section>
      </section> : null}

      <details ref={createPanelRef} className="scope-panel scan-create-disclosure" open={!runs.length}>
        <summary>
          <div>
          <p className="section-index">NEW SCAN RUN</p>
          <h2>{runs.length ? "再次扫描" : "创建受控任务"}</h2>
          <p className="panel-note">按目标、策略、授权三步确认；提交后会自动显示实时阶段结果。</p>
          </div>
          <span>{runs.length ? "展开设置" : "填写设置"}</span>
        </summary>
        <form onSubmit={createRun}>
          <label className="form-field"><span>扫描根域</span>
            <select aria-label="扫描根域" value={rootDomain} onChange={(event) => setRootDomain(event.target.value)} required disabled={!includedRoots.length}>
              {!includedRoots.length ? <option value="">尚无已确认根域</option> : null}
              {includedRoots.map((rule) => <option value={rule.value} key={rule.id}>{rule.value}</option>)}
            </select>
          </label>
          <label className="form-field"><span>1. 执行方式</span><select aria-label="执行方式" value={mode} onChange={(event) => setMode(event.target.value as "fixture" | "host")}>
            <option value="host">真实扫描（Docker 内置工具）</option>
            <option value="fixture">演示数据（仅开发测试）</option>
          </select></label>
          {mode === "host" ? <div className={compatibleToolCount > 0 ? "enterprise-alert" : "enterprise-alert is-error"} role="status">
            {tools === null ? "正在检查扫描工具…" : compatibleToolCount > 0 ? `真实工具已就绪：${compatibleToolCount}/${tools.length}` : <>没有可用扫描工具。<Link href="/system">查看系统诊断 →</Link></>}
          </div> : null}
          {mode === "host" ? <div className="resolver-note" role="note">
            <strong>独立公网解析已启用</strong>
            <span>DNS、HTTP、截图与网页发现使用独立 DoH，自动隔离全局代理产生的 198.18.0.0/15 映射；HTTP 代理仍只用于请求传输。</span>
          </div> : null}
          <label className="form-field"><span>2. 扫描深度</span><select aria-label="扫描深度" value={profile} onChange={(event) => {
            const selected = event.target.value as "quick" | "standard" | "deep" | "custom";
            setProfile(selected);
            if (selected !== "deep") setConfirmDeep(false);
            if (selected === "custom") { setFullPort(false); setConfirmFullPort(false); }
            if (selected === "quick") { setPortScan(true); setFullPort(false); setConfirmFullPort(false); }
            if (selected === "standard" || selected === "deep") setPortScan(true);
          }}>
            <option value="quick">Quick · 域名 / DNS / Web 常用端口 / HTTP</option>
            <option value="standard">Standard · 变体 / DNS / 安全端口 / 服务 / 爬取</option>
            <option value="deep">Deep · 扩展字典 / 扩展端口 / 深度爬取</option>
            <option value="custom">Custom · 闭合 JSON 策略</option>
          </select></label>
          {profile === "deep" ? <label className="authorization-box"><input type="checkbox" checked={confirmDeep} onChange={(event) => setConfirmDeep(event.target.checked)} required /><span><strong>二次确认 Deep 完全扫描</strong><small>Deep 扩大字典、变体、端口和爬取范围，但仍遵守 Scope、CDN 与速率边界。</small></span></label> : null}
          {profile === "custom" ? <label className="form-field form-field-wide"><span>Custom 扫描策略 JSON</span><textarea rows={8} value={customConfig} onChange={(event) => setCustomConfig(event.target.value)} spellCheck={false} /><small>仅接受后端定义的闭合字段；任意命令、未知键和越界数值都会被拒绝。</small></label> : null}
          {profile !== "custom" ? <label className="check-row"><input type="checkbox" checked={portScan} onChange={(event) => { setPortScan(event.target.checked); if (!event.target.checked) { setFullPort(false); setConfirmFullPort(false); } }} /><span>启用此 Profile 的端口发现与服务识别</span></label> : null}
          {profile !== "custom" ? <label className="check-row"><input type="checkbox" checked={screenshots} onChange={(event) => setScreenshots(event.target.checked)} /><span>生成网站截图（目标较多时可关闭，网站探测结果仍会入库）</span></label> : null}
          {profile !== "custom" && portScan ? <label className="check-row active-warning"><input type="checkbox" checked={fullPort} onChange={(event) => { setFullPort(event.target.checked); if (!event.target.checked) setConfirmFullPort(false); }} /><span>请求全端口 1–65535（仅 IN_SCOPE + OWNED IP）</span></label> : null}
          {fullPort ? <label className="authorization-box"><input type="checkbox" checked={confirmFullPort} onChange={(event) => setConfirmFullPort(event.target.checked)} required /><span><strong>二次确认全端口主动探测</strong><small>CDN/WAF、共享、未知、私网与保留 IP 仍会被后端拒绝。</small></span></label> : null}
          <label className="check-row"><input type="checkbox" checked={nuclei} onChange={(event) => { setNuclei(event.target.checked); if (!event.target.checked) setConfirmNuclei(false); }} /><span>启用 Nuclei 技术感知安全检查（先识别技术栈，再加载相关模板）</span></label>
          {nuclei ? <label className="authorization-box"><input type="checkbox" checked={confirmNuclei} onChange={(event) => setConfirmNuclei(event.target.checked)} required /><span><strong>二次确认安全模板探测</strong><small>默认按技术命中选择模板；禁止 DoS、fuzz、上传、默认口令、侵入式与 RCE 标签，结果只标记为未验证。</small></span></label> : null}
          <input value={proxyUrl} onChange={(event) => setProxyUrl(event.target.value)} placeholder="可选 HTTP/Burp 代理，例如 http://127.0.0.1:8080（禁止内嵌凭据）" />
          <p className="form-step-label">3. 授权与主动执行确认</p>
          <label className="check-row"><input type="checkbox" checked={authorized} onChange={(event) => setAuthorized(event.target.checked)} required /><span>再次确认已获得该目标的测试授权</span></label>
          {mode === "host" ? <label className="check-row active-warning"><input type="checkbox" checked={allowActive} onChange={(event) => setAllowActive(event.target.checked)} required /><span>允许调用当前 Profile 中已通过 Scope 策略的外部工具</span></label> : null}
          <button type="submit" disabled={creating || !rootDomain || (mode === "host" && compatibleToolCount === 0)}>{creating ? "正在入队" : mode === "host" ? "开始真实扫描" : "运行演示数据"}</button>
        </form>
      </details>

      <section className="scan-runs" aria-label="扫描历史">
        {runs.length ? runs.map((run) => {
          const execution = runExecutionPresentation(run, jobs[run.id] ?? []);
          return (
          <article className="scan-run-card" key={run.id}>
            <header>
              <div>
                <span className={`scan-status scan-${run.status.toLowerCase()}`}>{scanStatusLabel(run.status)}</span>
                <h2>{run.config_snapshot.root_domain ?? "未命名目标"}</h2>
                <small>{run.profile} · {run.config_snapshot.execution_mode} · {run.config_snapshot.port_scan_enabled ? (run.config_snapshot.full_port_scan ? "全端口请求" : "选定端口") : "端口关闭"} · {new Date(run.created_at).toLocaleString("zh-CN")}</small>
              </div>
              <div className="scan-actions">
                {run.status === "RUNNING" || run.status === "QUEUED" ? <button onClick={() => void action(run.id, "pause")}>暂停</button> : null}
                {run.status === "PAUSED" ? <button onClick={() => void action(run.id, "resume")}>恢复</button> : null}
                {!terminal.has(run.status) ? <button className="danger-action" onClick={() => void action(run.id, "cancel")}>取消</button> : null}
              </div>
            </header>
            <div className="run-metrics">
              <div><span>{execution.label}</span><strong>{execution.value}</strong><small>{execution.detail}</small>{execution.showProgress ? <progress max="100" value={run.progress} /> : null}</div>
              <div><span>攻击面覆盖置信度</span><strong>{run.coverage_level ?? "未评估"}</strong><small>{run.coverage_score === null ? "阶段 3 不以任务完成度推断覆盖率" : `${run.coverage_score}%`}</small></div>
            </div>
            {terminal.has(run.status) ? <div className="run-result-summary">
              <p>{runResultLine(run, jobs[run.id] ?? [])}</p>
              <div className="inventory-nav"><Link className="button-primary" href={`/projects/${projectId}/websites${evidenceModeQuery(run.config_snapshot.execution_mode)}`}>网站结果</Link><Link className="button-secondary" href={`/projects/${projectId}/scope${evidenceModeQuery(run.config_snapshot.execution_mode)}`}>全部资产</Link><Link className="button-secondary" href={`/projects/${projectId}/network${evidenceModeQuery(run.config_snapshot.execution_mode)}`}>网络结果</Link></div>
            </div> : null}
            <div className="job-list">
              {(jobs[run.id] ?? []).map((job) => (
                <details key={job.id} className={`scan-job job-${job.status.toLowerCase()}`} open={["RUNNING", "FAILED", "TIMEOUT", "PARTIAL_SUCCESS"].includes(job.status)}>
                  <summary><span>{String(job.sequence + 1).padStart(2, "0")}</span><strong>{adapterLabel(job.adapter_name)}</strong><small>{job.status === "RUNNING" ? jobElapsed(job, now) : jobResultLine(job)}</small><em>{scanStatusLabel(job.status)}</em></summary>
                  <dl>
                    <div><dt>尝试</dt><dd>{job.attempt}/{job.max_attempts}</dd></div>
                    <div><dt>耗时 / 上限</dt><dd>{jobElapsed(job, now)} / {formatDuration(job.timeout_seconds)}</dd></div>
                    <div><dt>阶段结果</dt><dd>{jobResultLine(job)}</dd></div>
                    <div><dt>结果</dt><dd>{jobIssueText(job) ?? "此阶段已正常完成"}</dd></div>
                    <div><dt>技术详情</dt><dd><code>{job.error_code ?? job.stdout_path ?? "无"}</code></dd></div>
                  </dl>
                  {(["FAILED", "TIMEOUT", "PARTIAL_SUCCESS", "SKIPPED"] as string[]).includes(job.status) && job.attempt < job.max_attempts ? <button onClick={() => void retry(job.id)}>重试该阶段</button> : null}
                </details>
              ))}
            </div>
          </article>
          );
        }) : <div className="empty-state"><span>NO SCAN RUNS</span><h2>尚无扫描任务。</h2><p>确认根域后，从上方启动 Docker 内置工具的真实扫描。</p></div>}
      </section>
      {runTotal > RUN_PAGE_SIZE ? <nav className="pagination-bar" aria-label="扫描历史分页">
        <button type="button" disabled={runPage === 1} onClick={() => setRunPage((page) => Math.max(1, page - 1))}>上一页</button>
        <span>第 {runPage} / {Math.ceil(runTotal / RUN_PAGE_SIZE)} 页 · 共 {runTotal} 次扫描</span>
        <button type="button" disabled={runPage >= Math.ceil(runTotal / RUN_PAGE_SIZE)} onClick={() => setRunPage((page) => page + 1)}>下一页</button>
      </nav> : null}
    </>
  );
}
