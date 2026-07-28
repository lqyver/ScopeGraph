"use client";

import Link from "next/link";
import { FormEvent, useCallback, useEffect, useMemo, useState } from "react";

import {
  apiRequest,
  CandidateRoot,
  CoverageAssessment,
  EnterpriseDiscoveryRun,
  errorMessage,
  Project,
  ReviewDecision,
  ReviewQueueItem,
} from "./api";

interface EnterpriseCenterProps {
  projectId: string;
}

const decisionLabels: Record<ReviewDecision, string> = {
  CONFIRM: "确认归属",
  ADD_TO_SCOPE: "确认并加入 Scope",
  EXCLUDE: "排除",
  MARK_THIRD_PARTY: "标记第三方",
  DEFER: "暂缓",
};

const sourceLabels: Record<string, string> = {
  "local-scope": "本地 Scope",
  "recorded-public-search": "录制公开证据",
  "duckduckgo-html": "DuckDuckGo 搜索",
  "bing-html": "Bing 搜索",
  "crtsh-domain-verify": "证书透明度（域名佐证）",
  "rdap-registrant": "RDAP 注册信息",
};

const sourceCategoryLabels: Record<string, string> = {
  local: "本地",
  fixture: "录制测试",
  "public-search": "公开检索",
  "certificate-transparency": "证书透明度",
  registration: "注册信息",
};

const sourceStatusLabels: Record<string, string> = {
  PENDING: "等待开始",
  RUNNING: "正在查询",
  COMPLETED: "完成",
  PARTIAL: "部分完成",
  UNAVAILABLE: "暂不可用",
  SKIPPED: "等待候选根域",
};

const stageLabels: Record<string, string> = {
  QUEUED: "等待工作器",
  "local-scope": "本地 Scope",
  "recorded-public-search": "录制公开证据",
  "public-search": "公开搜索",
  "candidate-corroboration": "候选归属佐证",
  COMPLETED: "汇总完成",
  FAILED: "执行失败",
};

function discoveryNotice(run: EnterpriseDiscoveryRun) {
  const sourceFailures = run.source_results
    .filter((item) => item.error)
    .map((item) => `${sourceLabels[item.source] ?? item.source}：${item.error}`);
  const corroboratedHint = run.summary.corroborated_candidate_count
    ? `；其中 ${run.summary.corroborated_candidate_count} 个候选获得独立来源交叉支持`
    : "";
  const rejectedHint = run.summary.rejected_value_count
    ? `；已忽略 ${run.summary.rejected_value_count} 个格式不合规的线索`
    : "";
  if (run.status === "RUNNING") {
    const stage = stageLabels[run.summary.stage ?? ""] ?? run.summary.stage ?? "来源收集";
    return `企业发现正在执行：${run.summary.progress_percent ?? 0}% · ${stage}。来源状态会自动刷新。`;
  }
  if (run.status === "FAILED") {
    return `发现未产生可用候选：${sourceFailures.join("；") || run.summary.failure_reason || "来源无结果"}${rejectedHint}`;
  }
  if (run.status === "PARTIAL_SUCCESS") {
    return `发现部分完成：${run.summary.candidate_count ?? 0} 个候选根域；${sourceFailures.join("；") || "部分来源未返回结果"}${corroboratedHint}${rejectedHint}`;
  }
  return `发现完成：${run.summary.candidate_count ?? 0} 个候选根域${corroboratedHint}`;
}

export function EnterpriseCenter({ projectId }: EnterpriseCenterProps) {
  const [project, setProject] = useState<Project | null>(null);
  const [candidates, setCandidates] = useState<CandidateRoot[]>([]);
  const [queue, setQueue] = useState<ReviewQueueItem[]>([]);
  const [coverage, setCoverage] = useState<CoverageAssessment | null>(null);
  const [mode, setMode] = useState<"local" | "fixture" | "public">("public");
  const [selected, setSelected] = useState<string[]>([]);
  const [reason, setReason] = useState("经授权管理员核验");
  const [manualDomain, setManualDomain] = useState("");
  const [lastRun, setLastRun] = useState<EnterpriseDiscoveryRun | null>(null);
  const [loading, setLoading] = useState(true);
  const [working, setWorking] = useState(false);
  const [activeRunId, setActiveRunId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      setError(null);
      const [projectData, candidateData, queueData, coverageData] = await Promise.all([
        apiRequest<Project>(`projects/${projectId}`),
        apiRequest<CandidateRoot[]>(`projects/${projectId}/candidate-root-domains`),
        apiRequest<ReviewQueueItem[]>(`projects/${projectId}/review-queue`),
        apiRequest<CoverageAssessment>(`projects/${projectId}/coverage`),
      ]);
      setProject(projectData);
      setCandidates(candidateData);
      setQueue(queueData);
      setCoverage(coverageData);
    } catch (caught) {
      setError(errorMessage(caught));
    } finally {
      setLoading(false);
    }
  }, [projectId]);

  useEffect(() => {
    const initial = window.setTimeout(() => void load(), 0);
    return () => window.clearTimeout(initial);
  }, [load]);

  useEffect(() => {
    if (!activeRunId) return;
    let cancelled = false;
    let timer: number | undefined;
    const poll = async () => {
      try {
        const run = await apiRequest<EnterpriseDiscoveryRun>(
          `projects/${projectId}/enterprise-discovery/${activeRunId}`,
        );
        if (cancelled) return;
        setLastRun(run);
        setNotice(discoveryNotice(run));
        if (run.status === "RUNNING") {
          timer = window.setTimeout(() => void poll(), 800);
          return;
        }
        setActiveRunId(null);
        setWorking(false);
        await load();
      } catch (caught) {
        if (cancelled) return;
        setError(errorMessage(caught));
        setActiveRunId(null);
        setWorking(false);
      }
    };
    void poll();
    return () => {
      cancelled = true;
      if (timer !== undefined) window.clearTimeout(timer);
    };
  }, [activeRunId, load, projectId]);

  const actionable = useMemo(
    () => queue.filter((item) => selected.includes(item.resource_id)),
    [queue, selected],
  );

  async function discover() {
    setWorking(true);
    setError(null);
    setNotice(null);
    try {
      const run = await apiRequest<EnterpriseDiscoveryRun>(
        `projects/${projectId}/enterprise-discovery`,
        {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ execution_mode: mode, aliases: [], async_execution: true }),
        },
      );
      setLastRun(run);
      setNotice(discoveryNotice(run));
      setActiveRunId(run.id);
    } catch (caught) {
      setError(errorMessage(caught));
      setWorking(false);
    }
  }

  async function applyBatch(decision: ReviewDecision) {
    if (!actionable.length) return;
    setWorking(true);
    setError(null);
    try {
      const result = await apiRequest<{ completed: number; failed: Array<{ message: string }> }>(
        `projects/${projectId}/reviews/batch`,
        {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            items: actionable.map((item) => ({
              resource_type: item.resource_type,
              resource_id: item.resource_id,
              decision,
              reason,
            })),
          }),
        },
      );
      setNotice(`已完成 ${result.completed} 项「${decisionLabels[decision]}」`);
      if (result.failed.length) setError(result.failed.map((item) => item.message).join("；"));
      setSelected([]);
      await load();
    } catch (caught) {
      setError(errorMessage(caught));
    } finally {
      setWorking(false);
    }
  }

  async function addCandidate(event: FormEvent) {
    event.preventDefault();
    setWorking(true);
    setError(null);
    try {
      await apiRequest(`projects/${projectId}/candidate-root-domains`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ domain: manualDomain, reason }),
      });
      setManualDomain("");
      setNotice("人工候选已加入待复核队列");
      await load();
    } catch (caught) {
      setError(errorMessage(caught));
    } finally {
      setWorking(false);
    }
  }

  if (loading) return <div className="loading-panel">正在读取企业归属证据…</div>;
  if (!project)
    return <div className="error-panel" role="alert"><strong>项目读取失败</strong><p>{error}</p></div>;

  return (
    <>
      <header className="enterprise-heading">
        <div>
          <p className="eyebrow">PHASE 5 / OWNERSHIP CONTROL</p>
          <h1>企业发现与人工复核</h1>
          <p>{project.company_name} · 候选不是授权，只有人工加入 Scope 后才允许主动扫描。</p>
          <p className="panel-note">推荐先运行公开被动发现；它只查询检索、证书透明度与公开注册证据，不会访问或扫描候选目标。</p>
        </div>
        <div className="enterprise-actions">
          <label>发现来源
            <select value={mode} onChange={(event) => setMode(event.target.value as typeof mode)}>
              <option value="local">本地证据</option>
              <option value="public">公开被动发现</option>
              <option value="fixture">录制数据（测试）</option>
            </select>
          </label>
          <button className="button-primary" type="button" disabled={working} onClick={() => void discover()}>
            {working ? "正在收集来源结果…" : "运行企业发现"}
          </button>
        </div>
      </header>

      {error && <div className="enterprise-alert is-error" role="alert">{error}</div>}
      {notice && <div className="enterprise-alert" role="status">{notice}</div>}
      {lastRun ? <section className="scope-panel" aria-label="企业发现来源结果">
        <p className="section-index">DISCOVERY SOURCE DIAGNOSTICS</p>
        <h2>来源结果</h2>
        {lastRun.status === "RUNNING" ? <p className="panel-note" aria-live="polite">
          实时进度：{lastRun.summary.progress_percent ?? 0}% · 当前阶段：{stageLabels[lastRun.summary.stage ?? ""] ?? lastRun.summary.stage ?? "来源收集"}。
          {lastRun.summary.source_running_count ?? 0} 个来源正在查询，{lastRun.summary.source_pending_count ?? 0} 个等待中。
        </p> : null}
        {lastRun.source_results.map((item) => <p className="run-source-note" key={item.source}>
          <strong>{sourceLabels[item.source] ?? item.source}</strong>
          {item.category ? ` · ${sourceCategoryLabels[item.category] ?? item.category}` : ""}
          {" · "}{sourceStatusLabels[item.status ?? "COMPLETED"] ?? item.status ?? "完成"}
          {" · "}{item.candidate_count} 个线索
          {item.attempted_count ? ` · ${item.completed_count ?? 0}/${item.attempted_count} 次请求完成` : ""}
          {item.error ? <><br /><small>未可用原因：{item.error}</small></> : item.skipped_reason ? <><br /><small>未执行原因：{item.skipped_reason}</small></> : item.status === "PENDING" ? <><br /><small>等待前序来源完成</small></> : item.status === "RUNNING" ? <><br /><small>正在查询，结果会自动更新</small></> : <><br /><small>本来源正常完成</small></>}
        </p>)}
        <p className="panel-note">
          覆盖率：{lastRun.summary.source_completed_count ?? 0} 个来源完成、
          {lastRun.summary.source_partial_count ?? 0} 个部分完成、
          {lastRun.summary.source_unavailable_count ?? 0} 个暂不可用；
          共 {lastRun.summary.source_successful_request_count ?? 0}/{lastRun.summary.source_attempted_count ?? 0} 次被动请求成功。
          {lastRun.summary.enrichment_seed_count ? ` 已优先佐证 ${lastRun.summary.enrichment_seed_count} 个候选根域。` : ""}
        </p>
        {lastRun.summary.rejected_value_count ? <p className="panel-note">
          已忽略 {lastRun.summary.rejected_value_count} 个格式不合规的来源线索。
        </p> : null}
        <p className="panel-note">所有公开来源只提供待复核线索，不会自动把候选加入 Scope 或启动扫描。</p>
      </section> : null}
      {candidates.some((candidate) => candidate.status === "CONFIRMED") ? (
        <div className="enterprise-alert" role="status">
          已有根域加入授权范围。<Link href={`/projects/${projectId}/scans`}>继续创建真实扫描 →</Link>
        </div>
      ) : null}

      <section className="coverage-panel" aria-labelledby="coverage-title">
        <div className="coverage-score">
          <span id="coverage-title">PROCESS COVERAGE</span>
          <strong>{coverage?.coverage_score ?? 0}</strong>
          <small>{coverage?.coverage_level ?? "LOW"}</small>
        </div>
        <div>
          <h2>任务完成 ≠ 资产完备</h2>
          <p>最近任务：{coverage?.task_status ?? "NOT_STARTED"}；覆盖度只衡量流程证据，不声称发现了全部真实资产。</p>
          <div className="coverage-factors">
            {coverage?.factors.map((factor) => (
              <span className={factor.completed ? "is-done" : ""} key={factor.key}>
                {factor.completed ? "✓" : "○"} {factor.label} +{factor.weight}
              </span>
            ))}
          </div>
        </div>
      </section>

      <section className="review-toolbar">
        <div>
          <p className="section-index">01 / REVIEW QUEUE</p>
          <h2>待复核 {queue.length} 项</h2>
        </div>
        <label>审计原因
          <input value={reason} minLength={3} onChange={(event) => setReason(event.target.value)} />
        </label>
        <div className="review-buttons">
          {(["ADD_TO_SCOPE", "EXCLUDE", "MARK_THIRD_PARTY", "DEFER"] as ReviewDecision[]).map((decision) => (
            <button type="button" disabled={working || !actionable.length || reason.length < 3} onClick={() => void applyBatch(decision)} key={decision}>
              {decisionLabels[decision]}
            </button>
          ))}
        </div>
      </section>

      <div className="candidate-list">
        {candidates.length ? candidates.map((candidate) => {
          const queued = queue.some((item) => item.resource_id === candidate.id);
          return (
            <article className="candidate-card" key={candidate.id}>
              <input
                aria-label={`选择 ${candidate.root_domain}`}
                type="checkbox"
                disabled={!queued}
                checked={selected.includes(candidate.id)}
                onChange={(event) => setSelected((current) => event.target.checked ? [...current, candidate.id] : current.filter((id) => id !== candidate.id))}
              />
              <div className="candidate-domain"><strong>{candidate.root_domain}</strong><span>{candidate.status}</span></div>
              <div className="candidate-score"><strong>{candidate.score}</strong><small>raw {candidate.raw_score}</small></div>
              <div className="evidence-chips">
                {candidate.evidence_summary.map((item) => <span key={item.signal}>{item.signal} {item.weight > 0 ? "+" : ""}{item.weight}</span>)}
              </div>
              <details><summary>查看 {candidate.evidence.length} 条原始评分证据</summary>
                <ul>{candidate.evidence.map((item, index) => <li key={`${item.evidence_type}-${index}`}><b>{item.evidence_type}</b> · {item.source_tool ?? "unknown"} · {new Date(item.observed_at).toLocaleString("zh-CN")}</li>)}</ul>
              </details>
            </article>
          );
        }) : <div className="empty-state"><span>NO CANDIDATES</span><h2>尚无候选根域。</h2><p>运行本地或公开被动发现；若来源无结果，系统会明确报告失败原因。</p></div>}
      </div>

      <form className="manual-candidate" onSubmit={(event) => void addCandidate(event)}>
        <div><p className="section-index">02 / MANUAL SUPPLEMENT</p><h2>补充候选根域</h2></div>
        <input aria-label="候选根域" required placeholder="example.com" value={manualDomain} onChange={(event) => setManualDomain(event.target.value)} />
        <button className="button-secondary" disabled={working || reason.length < 3}>加入待复核</button>
      </form>
      <p className="enterprise-back"><Link href="/projects">← 返回项目</Link></p>
    </>
  );
}
