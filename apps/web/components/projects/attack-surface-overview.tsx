import Link from "next/link";

import { AttackSurfaceItem, AttackSurfacePage } from "./api";
import { evidenceModeQuery, type EvidenceMode } from "./evidence-mode";

interface AttackSurfaceOverviewProps {
  projectId: string;
  data: AttackSurfacePage;
  compact?: boolean;
  mode?: EvidenceMode;
}

const priorityLabels = {
  urgent: "优先复核",
  high: "高优先级",
  review: "建议复核",
  observed: "已观察",
} as const;

function portLabel(port: AttackSurfaceItem["ports"][number]) {
  const service = [port.service?.name, port.service?.product, port.service?.version]
    .filter(Boolean)
    .join(" ");
  return `${port.ip}:${port.port}/${port.protocol}${service ? ` · ${service}` : ""}`;
}

export function AttackSurfaceOverview({
  projectId,
  data,
  compact = false,
  mode = "host",
}: AttackSurfaceOverviewProps) {
  const visibleItems = compact ? data.items.slice(0, 5) : data.items;
  const title = compact ? "优先复核目标" : "按域名聚合的攻击面";

  return (
    <section className={`attack-surface-panel${compact ? " is-compact" : ""}`}>
      <header className="attack-surface-heading">
        <div>
          <p className="section-index">DOMAIN-CENTRIC EVIDENCE</p>
          <h2>{title}</h2>
          <p>
            端口、网站、技术栈和自动化命中按同一域名归并；优先级只用于安排人工复核顺序，
            不代表已确认漏洞或资产归属。
          </p>
        </div>
        <Link className="button-secondary" href={`/projects/${projectId}/scope${evidenceModeQuery(mode)}`}>
          审核 Scope 与归属
        </Link>
      </header>

      <div className="attack-surface-summary" aria-label="攻击面摘要">
        <div><span>域名</span><strong>{data.summary.domains}</strong></div>
        <div><span>优先复核目标</span><strong>{data.summary.high_priority_targets}</strong></div>
        <div><span>开放端口</span><strong>{data.summary.open_ports}</strong></div>
        <div><span>技术指纹</span><strong>{data.summary.technologies}</strong></div>
        <div><span>存活网站</span><strong>{data.summary.active_websites}</strong></div>
        <div><span>待验证高危命中</span><strong>{data.summary.high_findings}</strong></div>
      </div>

      {data.environment_mappings_excluded ? (
        <p className="surface-data-note" role="status">
          已从此视图排除 {data.environment_mappings_excluded} 个代理/TUN 映射地址，避免把本地
          Fake-IP 当成真实目标。
        </p>
      ) : null}

      {!visibleItems.length ? (
        <div className="surface-empty">
          <strong>尚无可聚合域名</strong>
          <p>完成 DNS、端口或 Web 阶段后，这里会自动按域名汇总已有证据。</p>
        </div>
      ) : (
        <div className="attack-surface-list">
          {visibleItems.map((item) => (
            <article className="attack-surface-item" key={item.domain_asset_id}>
              <header className="surface-item-heading">
                <div>
                  <div className="surface-title-row">
                    <Link href={`/projects/${projectId}/scope${evidenceModeQuery(mode)}`} className="surface-domain">
                      {item.domain}
                    </Link>
                    <span className={`priority-badge priority-${item.priority_tier}`}>
                      {priorityLabels[item.priority_tier]} · {item.priority_score}
                    </span>
                  </div>
                  <p>
                    {item.scope_status} · {item.ownership_status} · 最近发现
                    {" "}{new Date(item.last_seen_at).toLocaleString("zh-CN")}
                  </p>
                </div>
                <div className="surface-counts" aria-label={`${item.domain} 计数`}>
                  <span>{item.ports.length} 端口</span>
                  <span>{item.technologies.length} 技术</span>
                  <span>{item.endpoint_count} 端点</span>
                  <span>{item.active_finding_count} 待验证</span>
                </div>
              </header>

              <div className="surface-reasons">
                {item.priority_reasons.map((reason) => <span key={reason}>{reason}</span>)}
              </div>

              <div className="surface-evidence-grid">
                <div>
                  <span className="surface-label">真实解析 IP</span>
                  <div className="surface-chip-list">
                    {item.resolved_ips.length
                      ? item.resolved_ips.map((ip) => <code key={ip}>{ip}</code>)
                      : <em>尚未获得可用解析 IP</em>}
                  </div>
                </div>
                <div>
                  <span className="surface-label">开放端口 / 服务</span>
                  <div className="surface-chip-list">
                    {item.ports.length
                      ? item.ports.map((port) => <code key={`${port.ip}-${port.port}-${port.protocol}`}>{portLabel(port)}</code>)
                      : <em>尚无开放端口记录</em>}
                  </div>
                </div>
                <div>
                  <span className="surface-label">技术栈</span>
                  <div className="technology-chips">
                    {item.technologies.length
                      ? item.technologies.map((technology) => <span key={technology}>{technology}</span>)
                      : <em>尚未识别技术栈</em>}
                  </div>
                </div>
                <div>
                  <span className="surface-label">网站 / 自动化命中</span>
                  <div className="surface-website-list">
                    {item.websites.length
                      ? item.websites.map((website) => (
                        <Link href={`/websites/${website.id}${evidenceModeQuery(mode)}`} key={website.id}>
                          <strong>{website.status_code ?? "ERR"}</strong>
                          <span>{website.title ?? website.url}</span>
                          <small>{website.endpoint_count} 端点</small>
                        </Link>
                      ))
                      : <em>尚无网站响应</em>}
                  </div>
                  {item.findings.length ? (
                    <div className="surface-finding-list">
                      {item.findings.map((finding) => (
                        <span key={finding.id} className={`surface-finding severity-${finding.severity}`}>
                          {finding.severity.toUpperCase()} · {finding.template_name}
                        </span>
                      ))}
                    </div>
                  ) : null}
                </div>
              </div>
            </article>
          ))}
        </div>
      )}
      {!compact && data.total > visibleItems.length ? (
        <p className="surface-data-note">当前显示前 {visibleItems.length} 个域名；其余域名仍保留在完整资产清单中。</p>
      ) : null}
    </section>
  );
}
