"use client";

import Link from "next/link";
import { FormEvent, useCallback, useEffect, useRef, useState } from "react";

import {
  apiRequest,
  AssetImportResult,
  AssetPage,
  errorMessage,
  Project,
  ProjectSummary,
  ScopeCheck,
  ScopeRule,
} from "./api";
import type { EvidenceMode } from "./evidence-mode";
import { useEvidenceMode } from "./use-evidence-mode";

interface ScopeManagerProps {
  projectId: string;
  initialMode?: EvidenceMode;
}

const typeLabels: Record<string, string> = {
  ROOT_DOMAIN: "根域及全部子域",
  DOMAIN: "精确域名",
  IP: "精确 IP",
  CIDR: "CIDR 网段",
  URL: "精确 URL",
};

const typeHelp: Record<string, string> = {
  ROOT_DOMAIN: "示例：example.com。不要包含 https://、路径或 www 子域。",
  DOMAIN: "示例：www.example.com。只填写完整域名，不包含协议或路径。",
  IP: "示例：203.0.113.10。",
  CIDR: "示例：203.0.113.0/24。",
  URL: "示例：https://www.example.com/path。",
};

export function ScopeManager({ projectId, initialMode = "host" }: ScopeManagerProps) {
  const [project, setProject] = useState<Project | null>(null);
  const [rules, setRules] = useState<ScopeRule[]>([]);
  const [assets, setAssets] = useState<AssetPage | null>(null);
  const [summary, setSummary] = useState<ProjectSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [ruleType, setRuleType] = useState("ROOT_DOMAIN");
  const [ruleValue, setRuleValue] = useState("");
  const [ruleAction, setRuleAction] = useState("INCLUDE");
  const [savingRule, setSavingRule] = useState(false);
  const [checkType, setCheckType] = useState("domain");
  const [checkValue, setCheckValue] = useState("");
  const [checkResult, setCheckResult] = useState<ScopeCheck | null>(null);
  const [importing, setImporting] = useState(false);
  const [importResult, setImportResult] = useState<AssetImportResult | null>(null);
  const [assetPage, setAssetPage] = useState(1);
  const [assetMode, setAssetMode] = useEvidenceMode(initialMode);
  const [assetType, setAssetType] = useState("");
  const [assetScope, setAssetScope] = useState("");
  const [refreshing, setRefreshing] = useState(false);
  const [lastUpdatedAt, setLastUpdatedAt] = useState<number | null>(null);
  const refreshInFlight = useRef(false);

  const load = useCallback(async (silent = false) => {
    if (refreshInFlight.current) return;
    refreshInFlight.current = true;
    if (silent) setRefreshing(true);
    try {
      setError(null);
      const params = new URLSearchParams({
        page: String(assetPage),
        page_size: "50",
        execution_mode: assetMode,
      });
      if (assetType) params.set("asset_type", assetType);
      if (assetScope) params.set("scope_status", assetScope);
      const [projectResult, ruleResult, assetResult, summaryResult] = await Promise.allSettled([
        apiRequest<Project>(`projects/${projectId}`),
        apiRequest<ScopeRule[]>(`projects/${projectId}/scope-rules`),
        apiRequest<AssetPage>(`projects/${projectId}/assets?${params.toString()}`),
        apiRequest<ProjectSummary>(`projects/${projectId}/summary`),
      ]);
      if (projectResult.status === "fulfilled") setProject(projectResult.value);
      if (ruleResult.status === "fulfilled") setRules(ruleResult.value);
      if (assetResult.status === "fulfilled") setAssets(assetResult.value);
      if (summaryResult.status === "fulfilled") setSummary(summaryResult.value);
      const failures = [projectResult, ruleResult, assetResult, summaryResult]
        .filter((result): result is PromiseRejectedResult => result.status === "rejected")
        .map((result) => errorMessage(result.reason));
      setError(failures.length ? `部分数据刷新失败：${Array.from(new Set(failures)).join("；")}` : null);
      setLastUpdatedAt(Date.now());
    } catch (caught) {
      setError(errorMessage(caught));
    } finally {
      setLoading(false);
      setRefreshing(false);
      refreshInFlight.current = false;
    }
  }, [assetMode, assetPage, assetScope, assetType, projectId]);

  useEffect(() => {
    const initial = window.setTimeout(() => void load(false), 0);
    const timer = window.setInterval(() => {
      if (document.visibilityState === "visible") void load(true);
    }, 5000);
    return () => {
      window.clearTimeout(initial);
      window.clearInterval(timer);
    };
  }, [load]);

  async function addRule(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setSavingRule(true);
    setError(null);
    try {
      const value = ruleValue.trim();
      if (["ROOT_DOMAIN", "DOMAIN"].includes(ruleType) && value.includes("://")) {
        throw new Error("域名规则不能包含 http:// 或 https://；如需完整网址请选择“精确 URL”。");
      }
      await apiRequest<ScopeRule>(`projects/${projectId}/scope-rules`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          rule_type: ruleType,
          value,
          action: ruleAction,
          source: "USER",
        }),
      });
      setRuleValue("");
      await load(true);
    } catch (caught) {
      setError(errorMessage(caught));
    } finally {
      setSavingRule(false);
    }
  }

  async function deleteRule(ruleId: string) {
    if (!window.confirm("删除这条 Scope 规则？后续主动任务将立即使用新的边界。")) return;
    try {
      await apiRequest<void>(`projects/${projectId}/scope-rules/${ruleId}`, {
        method: "DELETE",
      });
      await load(true);
    } catch (caught) {
      setError(errorMessage(caught));
    }
  }

  async function checkScope(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);
    try {
      setCheckResult(
        await apiRequest<ScopeCheck>(`projects/${projectId}/scope/check`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ asset_type: checkType, value: checkValue }),
        }),
      );
    } catch (caught) {
      setError(errorMessage(caught));
      setCheckResult(null);
    }
  }

  async function importFile(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const input = event.currentTarget.elements.namedItem("asset-file") as HTMLInputElement;
    const file = input.files?.[0];
    if (!file) return;
    setImporting(true);
    setImportResult(null);
    setError(null);
    try {
      const body = new FormData();
      body.append("file", file);
      setImportResult(
        await apiRequest<AssetImportResult>(`projects/${projectId}/assets/import`, {
          method: "POST",
          body,
        }),
      );
      input.value = "";
      await load(true);
    } catch (caught) {
      setError(errorMessage(caught));
    } finally {
      setImporting(false);
    }
  }

  if (loading) return <div className="loading-panel">正在加载 Scope 与资产…</div>;
  if (!project)
    return (
      <div className="error-panel">
        <strong>项目不可用</strong>
        <p>{error ?? "项目不存在或已归档删除。"}</p>
        <Link href="/projects">返回项目列表</Link>
      </div>
    );

  return (
    <>
      <section className="project-context">
        <div>
          <p className="section-index">AUTHORIZED PROJECT / {project.status}</p>
          <h1>{project.name}</h1>
          <p>{project.company_name}</p>
        </div>
        <div className="context-metrics">
          <div>
            <span>Scope 规则</span>
            <strong>{summary?.scope_rule_count ?? 0}</strong>
          </div>
          <div>
            <span>已导入资产</span>
            <strong>{summary?.asset_count ?? 0}</strong>
          </div>
          <div>
            <span>扫描任务</span>
            <strong><Link href={`/projects/${projectId}/scans`}>任务中心 →</Link></strong>
          </div>
          <div>
            <span>网络清单</span>
            <strong><Link href={`/projects/${projectId}/network`}>IP / 端口 →</Link></strong>
          </div>
        </div>
      </section>

      {error ? <p className="form-error global-error" role="alert">{error}</p> : null}

      <div className="scope-layout">
        <section className="scope-panel scope-rules-panel">
          <div className="panel-heading">
            <div>
              <p className="section-index">SCOPE RULES</p>
              <h2>授权边界</h2>
            </div>
            <span className="guard-badge">排除优先</span>
          </div>

          <form className="inline-rule-form" onSubmit={addRule}>
            <select aria-label="规则类型" value={ruleType} onChange={(event) => setRuleType(event.target.value)}>
              {Object.entries(typeLabels).map(([value, label]) => (
                <option key={value} value={value}>{label}</option>
              ))}
            </select>
            <input
              aria-label="规则值"
              value={ruleValue}
              onChange={(event) => setRuleValue(event.target.value)}
              placeholder={ruleType === "CIDR" ? "192.0.2.0/24" : "example.com"}
              required
              spellCheck={false}
            />
            <select aria-label="规则动作" value={ruleAction} onChange={(event) => setRuleAction(event.target.value)}>
              <option value="INCLUDE">纳入</option>
              <option value="EXCLUDE">排除</option>
            </select>
            <button type="submit" disabled={savingRule}>{savingRule ? "保存中" : "添加规则"}</button>
          </form>
          <p className="panel-note">{typeHelp[ruleType]}</p>

          <div className="rule-list">
            {rules.length ? rules.map((rule) => (
              <article className={`rule-row rule-${rule.action.toLowerCase()}`} key={rule.id}>
                <span className="rule-action">{rule.action === "INCLUDE" ? "纳入" : "排除"}</span>
                <div>
                  <small>{typeLabels[rule.rule_type]}</small>
                  <strong>{rule.value}</strong>
                </div>
                <button type="button" onClick={() => void deleteRule(rule.id)} aria-label={`删除 ${rule.value}`}>
                  删除
                </button>
              </article>
            )) : <p className="panel-empty">尚无 Scope。任何主动目标都会被拒绝。</p>}
          </div>
        </section>

        <aside className="scope-panel scope-check-panel">
          <p className="section-index">DOUBLE-CHECK GUARD</p>
          <h2>边界判定</h2>
          <p>在未来创建主动任务前，业务服务和执行器都会调用相同规则。</p>
          <form onSubmit={checkScope}>
            <select value={checkType} onChange={(event) => setCheckType(event.target.value)} aria-label="资产类型">
              <option value="domain">域名</option>
              <option value="ip">IP</option>
              <option value="url">URL</option>
            </select>
            <input
              value={checkValue}
              onChange={(event) => setCheckValue(event.target.value)}
              placeholder="输入待判定目标"
              required
              spellCheck={false}
            />
            <button type="submit">检查</button>
          </form>
          {checkResult ? (
            <div className={`check-result ${checkResult.active_allowed ? "check-allowed" : "check-denied"}`}>
              <strong>{checkResult.active_allowed ? "允许派生主动任务" : "禁止主动任务"}</strong>
              <span>{checkResult.status}</span>
              <code>{checkResult.normalized_value}</code>
              <p>{checkResult.reason}</p>
            </div>
          ) : null}
        </aside>
      </div>

      <section className="scope-panel asset-panel">
        <div className="panel-heading">
          <div>
            <p className="section-index">SEED ASSETS</p>
            <h2>资产清单</h2>
          </div>
          <form className="import-form" onSubmit={importFile}>
            <input id="asset-file" name="asset-file" type="file" accept=".txt,.csv,.json" required />
            <button type="submit" disabled={importing}>{importing ? "导入中" : "导入文件"}</button>
          </form>
        </div>
        <div className="website-toolbar" aria-label="资产来源筛选">
          <label><span>数据来源</span><select value={assetMode} onChange={(event) => { setAssetMode(event.target.value as "host" | "fixture"); setAssetPage(1); }}><option value="host">真实扫描与人工导入</option><option value="fixture">演示扫描与人工导入</option></select></label>
          <label><span>资产类型</span><select value={assetType} onChange={(event) => { setAssetType(event.target.value); setAssetPage(1); }}><option value="">全部类型</option><option value="domain">域名</option><option value="ip">IP</option><option value="url">URL</option><option value="service">服务</option><option value="certificate">证书</option><option value="icp_record">备案记录</option></select></label>
          <label><span>Scope 状态</span><select value={assetScope} onChange={(event) => { setAssetScope(event.target.value); setAssetPage(1); }}><option value="">全部状态</option><option value="IN_SCOPE">范围内</option><option value="PENDING_REVIEW">待审核</option><option value="THIRD_PARTY">第三方</option><option value="CDN_SHARED">CDN / 共享</option><option value="EXCLUDED">已排除</option><option value="OUT_OF_SCOPE">范围外</option></select></label>
          <button className="button-secondary" type="button" disabled={refreshing} onClick={() => void load(true)}>{refreshing ? "刷新中" : "立即刷新"}</button>
        </div>
        <div className="inventory-live-note" role="status"><span className="live-indicator">自动更新</span><span>筛选结果 {assets?.total ?? 0} 项 · 项目总资产 {summary?.asset_count ?? 0} 项{lastUpdatedAt ? ` · ${new Date(lastUpdatedAt).toLocaleTimeString("zh-CN")} 同步` : ""}</span></div>
        <p className="panel-note">支持 UTF-8 TXT、CSV、JSON，最大 10 MiB。重复导入不会生成重复资产。</p>
        {importResult ? (
          <div className="import-result" role="status">
            新增 <strong>{importResult.created_count}</strong>，重复 {importResult.duplicate_count}，拒绝 {importResult.rejected_count}
          </div>
        ) : null}
        <div className="asset-table-wrap">
          <table className="asset-table">
            <thead>
              <tr><th>类型</th><th>原始值</th><th>规范化值</th><th>Scope</th><th>归属</th></tr>
            </thead>
            <tbody>
              {assets?.items.length ? assets.items.map((asset) => (
                <tr key={asset.id}>
                  <td>{asset.asset_type}</td>
                  <td>{asset.display_value}</td>
                  <td><code>{asset.normalized_value}</code></td>
                  <td><span className={`scope-state state-${asset.scope_status.toLowerCase()}`}>{asset.scope_status}</span></td>
                  <td>{asset.ownership_status}</td>
                </tr>
              )) : (
                <tr><td colSpan={5} className="table-empty">当前来源或筛选条件下暂无资产；扫描进行时本页会每 5 秒自动更新。</td></tr>
              )}
            </tbody>
          </table>
        </div>
        {(assets?.total ?? 0) > 50 ? <nav className="pagination-bar" aria-label="资产分页">
          <button type="button" disabled={assetPage === 1} onClick={() => setAssetPage((page) => Math.max(1, page - 1))}>上一页</button>
          <span>第 {assetPage} / {Math.ceil((assets?.total ?? 0) / 50)} 页</span>
          <button type="button" disabled={assetPage >= Math.ceil((assets?.total ?? 0) / 50)} onClick={() => setAssetPage((page) => page + 1)}>下一页</button>
        </nav> : null}
      </section>
    </>
  );
}
