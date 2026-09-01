"use client";

import Image from "next/image";
import Link from "next/link";
import { useCallback, useEffect, useState } from "react";

import { apiRequest, errorMessage, WebsiteDetail } from "./api";
import { evidenceModeQuery, type EvidenceMode } from "./evidence-mode";

interface WebsiteDetailProps {
  websiteId: string;
  initialMode?: EvidenceMode;
}

function formatDate(value: string | null): string {
  return value ? new Date(value).toLocaleString("zh-CN") : "—";
}

export function WebsiteDetailView({ websiteId, initialMode = "host" }: WebsiteDetailProps) {
  const [website, setWebsite] = useState<WebsiteDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      setError(null);
      setWebsite(
        await apiRequest<WebsiteDetail>(
          `websites/${websiteId}${evidenceModeQuery(initialMode)}`,
        ),
      );
    } catch (caught) {
      setError(errorMessage(caught));
    } finally {
      setLoading(false);
    }
  }, [initialMode, websiteId]);

  useEffect(() => {
    const initial = window.setTimeout(() => void load(), 0);
    return () => window.clearTimeout(initial);
  }, [load]);

  if (loading) return <div className="loading-panel">正在读取网站证据链…</div>;
  if (!website)
    return <div className="error-panel" role="alert"><strong>网站详情不可用</strong><p>{error}</p><button type="button" onClick={() => void load()}>重试</button></div>;

  return (
    <>
      <section className="website-detail-hero">
        <div>
          <p className="section-index">WEBSITE EVIDENCE / {website.status_code ?? "ERROR"}</p>
          <h1>{website.title ?? "未提取标题"}</h1>
          <code>{website.url}</code>
        </div>
        <div className="inventory-nav">
          <Link className="button-secondary" href={`/projects/${website.project_id}/websites${evidenceModeQuery(initialMode)}`}>返回网站清单</Link>
          <Link className="button-secondary" href={`/projects/${website.project_id}/scans`}>任务证据</Link>
        </div>
      </section>

      {error ? <p className="form-error global-error" role="alert">{error}</p> : null}

      <section className="website-detail-layout">
        <div className="detail-capture">
          {website.screenshot_path ? (
            <Image src={`/api/backend/websites/${website.id}/screenshot${evidenceModeQuery(initialMode)}`} alt={`${website.title ?? website.url} 页面截图`} width={1280} height={720} unoptimized priority />
          ) : (
            <span className="capture-missing"><b>NO CAPTURE</b><small>截图任务失败，但网站元数据已保留</small></span>
          )}
        </div>
        <dl className="detail-facts">
          <div><dt>Scope / 归属</dt><dd>{website.scope_status} · {website.ownership_status}</dd></div>
          <div><dt>最终 URL</dt><dd>{website.final_url ?? "—"}</dd></div>
          <div><dt>网络端点</dt><dd>{website.ip ?? "—"}:{website.port ?? "—"}</dd></div>
          <div><dt>响应</dt><dd>{website.status_code ?? "ERR"} · {website.snapshot?.response_time_ms ?? "—"} ms</dd></div>
          <div><dt>内容</dt><dd>{website.content_type ?? "—"} · {website.snapshot?.content_length ?? "—"} bytes</dd></div>
          <div><dt>服务器</dt><dd>{website.snapshot?.server_header ?? "—"}</dd></div>
          <div><dt>首次 / 最近发现</dt><dd>{formatDate(website.first_seen_at)}<br />{formatDate(website.last_seen_at)}</dd></div>
          <div><dt>页面 / favicon 哈希</dt><dd className="hash-value">{website.snapshot?.body_hash ?? "—"}<br />{website.snapshot?.favicon_hash ?? "—"}</dd></div>
        </dl>
      </section>

      <section className="detail-grid">
        <article className="scope-panel">
          <p className="section-index">TECHNOLOGY & EDGE</p><h2>技术栈与边缘设施</h2>
          <div className="tag-list">{website.technology_details.length ? website.technology_details.map((item) => <span key={`${item.name}:${item.version}`}>{item.name}{item.version ? ` ${item.version}` : ""}</span>) : <em>未识别技术指纹</em>}</div>
          <dl className="compact-facts"><div><dt>CDN / WAF</dt><dd>{website.cdn_waf.join(" · ") || "未识别"}</dd></div><div><dt>响应头</dt><dd>{Object.keys(website.snapshot?.response_headers ?? {}).length} 个安全保留字段</dd></div></dl>
        </article>
        <article className="scope-panel">
          <p className="section-index">TLS CERTIFICATES</p><h2>TLS 证书</h2>
          {website.certificates.length ? website.certificates.map((certificate) => (
            <dl className="certificate-card" key={certificate.id}>
              <div><dt>主体</dt><dd>{certificate.subject ?? "—"}</dd></div>
              <div><dt>签发者</dt><dd>{certificate.issuer ?? "—"}</dd></div>
              <div><dt>有效期</dt><dd>{formatDate(certificate.not_before)} → {formatDate(certificate.not_after)}</dd></div>
              <div><dt>SAN</dt><dd>{certificate.san.join(" · ") || "—"}</dd></div>
              <div><dt>SHA-256</dt><dd className="hash-value">{certificate.fingerprint_sha256}</dd></div>
            </dl>
          )) : <p className="panel-note">当前快照没有可验证的 TLS 证书。</p>}
        </article>
      </section>

      <section className="scope-panel asset-panel">
        <div className="panel-heading"><div><p className="section-index">ICP / PUBLIC SECURITY</p><h2>备案与主体证据</h2></div><span className="guard-badge">{website.icp_status}</span></div>
        {website.filing_links.length ? <div className="filing-grid">{website.filing_links.map((filing) => (
          <article key={filing.record_id}>
            <span>{filing.record_kind} · {filing.association_status}</span>
            <h3>{filing.display_number}</h3>
            <p>{filing.subject_name ?? "未提取主体"}</p>
            <blockquote>{filing.evidence_excerpt}</blockquote>
            <small>来源：{filing.source_url}{filing.official_confirmed ? " · 官方已核验" : " · 页面提取/推断"}</small>
          </article>
        ))}</div> : <p className="panel-note">当前页面与根域均未发现备案证据。</p>}
      </section>

      <section className="scope-panel asset-panel">
        <div className="panel-heading"><div><p className="section-index">KATANA ENDPOINTS</p><h2>端点与访问边界</h2></div><span className="guard-badge">GET / HEAD ONLY</span></div>
        <div className="asset-table-wrap"><table className="asset-table"><thead><tr><th>端点</th><th>类型</th><th>方法</th><th>Scope</th><th>实际访问</th><th>状态</th></tr></thead><tbody>{website.endpoints.length ? website.endpoints.map((endpoint) => (
          <tr key={endpoint.id}><td><code>{endpoint.normalized_url}</code></td><td>{endpoint.kind}</td><td>{endpoint.method}</td><td>{endpoint.scope_status}</td><td>{endpoint.actively_visited ? "是" : "否，仅记录"}</td><td>{endpoint.status_code ?? "—"}</td></tr>
        )) : <tr><td className="table-empty" colSpan={6}>当前网站没有爬虫端点记录。</td></tr>}</tbody></table></div>
      </section>

      <details className="raw-evidence"><summary>查看结构化原始证据摘要</summary><pre>{JSON.stringify(website.snapshot, null, 2)}</pre></details>
    </>
  );
}
