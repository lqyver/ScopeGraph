"use client";

import Image from "next/image";
import Link from "next/link";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import {
  apiRequest,
  Endpoint,
  errorMessage,
  ICPRecord,
  Project,
  WebsitePage,
} from "./api";
import { filterWebsites, websiteStats } from "./website-utils";

interface WebsiteInventoryProps {
  projectId: string;
}

const filingLabels = {
  PAGE_DIRECT: "页面直接证据",
  ROOT_DOMAIN_INFERRED: "根域关联推断",
  SUBJECT_MATCH: "主体一致",
  RELATED_SUBJECT: "关联主体",
  SUBJECT_CONFLICT: "主体冲突",
  NOT_FOUND: "未发现",
  NOT_APPLICABLE: "不适用",
  PENDING_MANUAL_VERIFY: "待人工核验",
  HISTORICAL: "历史记录",
};

function TechnologyChips({ technologies, limit = 5 }: { technologies: string[]; limit?: number }) {
  const visible = technologies.slice(0, limit);
  if (!visible.length) return <span className="technology-empty">未识别</span>;
  return <div className="technology-chips">
    {visible.map((technology) => <span key={technology}>{technology}</span>)}
    {technologies.length > limit ? <span className="technology-more">+{technologies.length - limit}</span> : null}
  </div>;
}

export function WebsiteInventory({ projectId }: WebsiteInventoryProps) {
  const [project, setProject] = useState<Project | null>(null);
  const [data, setData] = useState<WebsitePage | null>(null);
  const [filings, setFilings] = useState<ICPRecord[]>([]);
  const [endpoints, setEndpoints] = useState<Endpoint[]>([]);
  const [view, setView] = useState<"cards" | "table">("table");
  const [query, setQuery] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [page, setPage] = useState(1);
  const [mode, setMode] = useState<"host" | "fixture">("host");
  const [refreshing, setRefreshing] = useState(false);
  const [lastUpdatedAt, setLastUpdatedAt] = useState<number | null>(null);
  const refreshInFlight = useRef(false);

  const load = useCallback(async (silent = false) => {
    if (refreshInFlight.current) return;
    refreshInFlight.current = true;
    if (silent) setRefreshing(true);
    try {
      setError(null);
      const [projectResult, websiteResult, filingResult, endpointResult] = await Promise.allSettled([
        apiRequest<Project>(`projects/${projectId}`),
        apiRequest<WebsitePage>(`projects/${projectId}/websites?page=${page}&page_size=50&execution_mode=${mode}`),
        apiRequest<ICPRecord[]>(`projects/${projectId}/icp-records`),
        apiRequest<Endpoint[]>(`projects/${projectId}/endpoints?execution_mode=${mode}&limit=200`),
      ]);
      if (projectResult.status === "fulfilled") setProject(projectResult.value);
      if (websiteResult.status === "fulfilled") setData(websiteResult.value);
      if (filingResult.status === "fulfilled") setFilings(filingResult.value);
      if (endpointResult.status === "fulfilled") setEndpoints(endpointResult.value);
      const failures = [projectResult, websiteResult, filingResult, endpointResult]
        .filter((result): result is PromiseRejectedResult => result.status === "rejected")
        .map((result) => errorMessage(result.reason));
      setError(failures.length ? `部分证据刷新失败：${Array.from(new Set(failures)).join("；")}` : null);
      setLastUpdatedAt(Date.now());
    } catch (caught) {
      setError(errorMessage(caught));
    } finally {
      setLoading(false);
      setRefreshing(false);
      refreshInFlight.current = false;
    }
  }, [mode, page, projectId]);

  useEffect(() => {
    const initial = window.setTimeout(() => void load(false), 0);
    const timer = window.setInterval(() => {
      if (document.visibilityState === "visible") void load(true);
    }, 5000);
    return () => { window.clearTimeout(initial); window.clearInterval(timer); };
  }, [load]);

  const visible = useMemo(() => filterWebsites(data?.items ?? [], query), [data, query]);
  const stats = useMemo(() => websiteStats(data?.items ?? []), [data]);
  const pendingExternal = endpoints.filter(
    (item) => item.kind === "EXTERNAL_LINK" && item.scope_status === "PENDING_REVIEW",
  );

  if (loading) return <div className="loading-panel">正在组装网站证据视图…</div>;
  if (!project || !data)
    return (
      <div className="error-panel" role="alert">
        <strong>网站清单读取失败</strong>
        <p>{error ?? "项目不存在"}</p>
        <button type="button" onClick={() => void load()}>重试</button>
      </div>
    );

  return (
    <>
      <section className="project-context website-context">
        <div>
          <p className="section-index">WEB INTELLIGENCE / EVIDENCE FIRST</p>
          <h1>{project.name}</h1>
          <p>截图、TLS、技术栈、备案和爬虫端点均保留来源；推断证据不会冒充页面直接证据。</p>
        </div>
        <div className="inventory-nav">
          <Link className="button-secondary" href={`/projects/${projectId}/scope`}>Scope 与资产</Link>
          <Link className="button-secondary" href={`/projects/${projectId}/network`}>网络清单</Link>
          <Link className="button-secondary" href={`/projects/${projectId}/scans`}>任务中心</Link>
        </div>
      </section>

      {error ? <p className="form-error global-error" role="alert">{error}</p> : null}
      <section className="inventory-summary website-summary">
        <div><span>网站总数</span><strong>{data.total}</strong></div>
        <div><span>本页存活</span><strong>{stats.alive}</strong></div>
        <div><span>本页截图</span><strong>{stats.screenshots}</strong></div>
        <div><span>本页技术指纹</span><strong>{stats.technologies}</strong></div>
        <div><span>备案记录</span><strong>{filings.length}</strong></div>
        <div><span>待审外部链接</span><strong>{pendingExternal.length}</strong></div>
      </section>

      <section className="website-toolbar" aria-label="网站视图控制">
        <label>
          <span className="sr-only">搜索网站</span>
          <input
            type="search"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="搜索 URL、标题、IP、技术栈或 CDN…"
          />
        </label>
        <label><span className="sr-only">数据来源</span><select value={mode} onChange={(event) => { setMode(event.target.value as "host" | "fixture"); setPage(1); }}><option value="host">真实扫描结果</option><option value="fixture">演示扫描结果</option></select></label>
        <div className="view-switch" role="group" aria-label="展示方式">
          <button type="button" aria-pressed={view === "table"} onClick={() => setView("table")}>域名表</button>
          <button type="button" aria-pressed={view === "cards"} onClick={() => setView("cards")}>截图墙</button>
        </div>
        <button className="button-secondary" type="button" disabled={refreshing} onClick={() => void load(true)}>{refreshing ? "刷新中" : "刷新"}</button>
      </section>
      <div className="inventory-live-note" role="status"><span className="live-indicator">自动更新</span><span>扫描中的网站、截图、端点与备案证据每 5 秒同步{lastUpdatedAt ? ` · 最近更新 ${new Date(lastUpdatedAt).toLocaleTimeString("zh-CN")}` : ""}</span></div>

      {!visible.length ? (
        <section className="empty-state website-empty">
          <span>{data.total ? "NO MATCHES" : "NO WEBSITES"}</span>
          <h2>{data.total ? "没有符合当前搜索条件的网站。" : "扫描链尚未发现存活网站。"}</h2>
          <p>{data.total ? "清除搜索词后可恢复完整清单。" : "从任务中心启动包含 httpx 的扫描，截图失败不会阻止网站入库。"}</p>
        </section>
      ) : view === "cards" ? (
        <section className="website-grid" aria-label="网站截图墙">
          {visible.map((website) => (
            <article className="website-card" key={website.id}>
              <Link className="website-capture" href={`/websites/${website.id}`} aria-label={`查看 ${website.title ?? website.url} 详情`}>
                {website.screenshot_path ? (
                  <Image
                    src={`/api/backend/websites/${website.id}/screenshot`}
                    alt={`${website.title ?? website.url} 页面截图`}
                    width={1280}
                    height={720}
                    unoptimized
                  />
                ) : (
                  <span className="capture-missing"><b>NO CAPTURE</b><small>截图失败未影响网站入库</small></span>
                )}
              </Link>
              <div className="website-card-body">
                <div className="website-card-status">
                  <span className={website.is_alive ? "is-live" : "is-down"}>{website.status_code ?? "ERR"}</span>
                  <span>{website.scope_status}</span>
                  <span>{website.ownership_status}</span>
                </div>
                <h2>{website.title ?? "未提取标题"}</h2>
                <code>{website.url}</code>
                <dl>
                  <div><dt>端点</dt><dd>{website.ip ?? "—"}:{website.port ?? "—"}</dd></div>
                  <div><dt>技术</dt><dd><TechnologyChips technologies={website.technologies} limit={3} /></dd></div>
                  <div><dt>CDN/WAF</dt><dd>{website.cdn_waf.join(" · ") || "未识别"}</dd></div>
                  <div><dt>备案</dt><dd>{filingLabels[website.icp_status]}</dd></div>
                </dl>
                <Link className="website-detail-link" href={`/websites/${website.id}`}>查看完整证据 →</Link>
              </div>
            </article>
          ))}
        </section>
      ) : (
        <section className="scope-panel website-table-panel">
          <div className="asset-table-wrap">
            <table className="asset-table website-table">
              <thead><tr><th>网站</th><th>状态</th><th>IP / 端口</th><th>技术栈</th><th>CDN/WAF</th><th>备案证据</th><th>端点</th></tr></thead>
              <tbody>{visible.map((website) => (
                <tr key={website.id}>
                  <td><Link href={`/websites/${website.id}`}><strong>{website.title ?? "未提取标题"}</strong><code>{website.url}</code></Link></td>
                  <td><span className={`scope-state ${website.is_alive ? "state-in_scope" : "state-out_of_scope"}`}>{website.status_code ?? "ERR"}</span></td>
                  <td>{website.ip ?? "—"}:{website.port ?? "—"}</td>
                  <td><TechnologyChips technologies={website.technologies} /></td>
                  <td>{website.cdn_waf.join(" · ") || "—"}</td>
                  <td>{filingLabels[website.icp_status]}</td>
                  <td>{website.endpoint_count}</td>
                </tr>
              ))}</tbody>
            </table>
          </div>
        </section>
      )}

      {data.total > data.page_size ? <nav className="pagination-bar" aria-label="网站分页">
        <button type="button" disabled={page === 1} onClick={() => setPage((value) => Math.max(1, value - 1))}>上一页</button>
        <span>第 {page} / {Math.ceil(data.total / data.page_size)} 页 · 搜索仅作用于当前页</span>
        <button type="button" disabled={page >= Math.ceil(data.total / data.page_size)} onClick={() => setPage((value) => value + 1)}>下一页</button>
      </nav> : null}

      {pendingExternal.length ? (
        <section className="scope-panel asset-panel pending-links">
          <div className="panel-heading"><div><p className="section-index">FEEDBACK LOOP</p><h2>新根域待审核</h2></div><span className="guard-badge">NO AUTO SCAN</span></div>
          <p className="panel-note">Katana 只记录这些外部链接；其根域进入待审核，不会自动派生 DNS、端口或 Web 任务。</p>
          <div className="endpoint-chips">{pendingExternal.slice(0, 20).map((item) => <code key={item.id}>{item.normalized_url}</code>)}</div>
        </section>
      ) : null}
    </>
  );
}
