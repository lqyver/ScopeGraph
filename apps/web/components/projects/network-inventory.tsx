"use client";

import Link from "next/link";
import { FormEvent, useCallback, useEffect, useState } from "react";

import {
  AttackSurfacePage,
  apiRequest,
  errorMessage,
  IPClassification,
  IPInventory,
  IPInventoryPage,
  PortInventory,
  PortInventoryPage,
  Project,
  ScanJob,
  ScanRunOverviewPage,
} from "./api";
import { AttackSurfaceOverview } from "./attack-surface-overview";

interface NetworkInventoryProps {
  projectId: string;
}

const classifications: IPClassification[] = [
  "OWNED",
  "CLOUD_SERVER",
  "SHARED_HOSTING",
  "CDN_WAF",
  "UNKNOWN",
  "PRIVATE_RESERVED",
];

export function NetworkInventory({ projectId }: NetworkInventoryProps) {
  const [project, setProject] = useState<Project | null>(null);
  const [ips, setIps] = useState<IPInventory[]>([]);
  const [ports, setPorts] = useState<PortInventory[]>([]);
  const [assetId, setAssetId] = useState("");
  const [classification, setClassification] = useState<IPClassification>("UNKNOWN");
  const [reason, setReason] = useState("");
  const [saving, setSaving] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [ipPage, setIpPage] = useState(1);
  const [portPage, setPortPage] = useState(1);
  const [ipTotal, setIpTotal] = useState(0);
  const [portTotal, setPortTotal] = useState(0);
  const [ignoredMappings, setIgnoredMappings] = useState(0);
  const [latestPortJob, setLatestPortJob] = useState<ScanJob | null>(null);
  const [attackSurface, setAttackSurface] = useState<AttackSurfacePage | null>(null);

  const load = useCallback(async () => {
    try {
      const [projectData, ipData, portData, runData, surfaceData] = await Promise.all([
        apiRequest<Project>(`projects/${projectId}`),
        apiRequest<IPInventoryPage>(`projects/${projectId}/ips-page?page=${ipPage}&page_size=100`),
        apiRequest<PortInventoryPage>(`projects/${projectId}/ports-page?page=${portPage}&page_size=100`),
        apiRequest<ScanRunOverviewPage>(`projects/${projectId}/scan-runs-overview?page=1&page_size=10`),
        apiRequest<AttackSurfacePage>(`projects/${projectId}/attack-surface?page=1&page_size=200`),
      ]);
      setProject(projectData);
      setIps(ipData.items);
      setPorts(portData.items);
      setIpTotal(ipData.total);
      setPortTotal(portData.total);
      setIgnoredMappings(ipData.ignored_environment_mappings);
      setAttackSurface(surfaceData);
      setLatestPortJob(
        runData.items.flatMap((item) => item.jobs).find((job) => job.adapter_name === "naabu") ?? null,
      );
      setAssetId((current) => ipData.items.some((item) => item.asset_id === current) ? current : ipData.items[0]?.asset_id || "");
      setError(null);
    } catch (caught) {
      setError(errorMessage(caught));
    } finally {
      setLoading(false);
    }
  }, [ipPage, portPage, projectId]);

  useEffect(() => {
    const initial = window.setTimeout(() => void load(), 0);
    return () => window.clearTimeout(initial);
  }, [load]);

  async function classify(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setSaving(true);
    setError(null);
    try {
      await apiRequest<IPInventory>(`projects/${projectId}/ips/${assetId}`, {
        method: "PATCH",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ classification, reason }),
      });
      setReason("");
      await load();
    } catch (caught) {
      setError(errorMessage(caught));
    } finally {
      setSaving(false);
    }
  }

  if (loading) return <div className="loading-panel">正在加载网络清单…</div>;
  if (!project) return <div className="error-panel">{error ?? "项目不存在"}</div>;

  const scanTargets = Number(latestPortJob?.result_summary.scan_targets ?? 0);
  const testedPorts = Number(latestPortJob?.result_summary.ports_tested_per_target ?? 0);
  const candidateChecks = Number(latestPortJob?.result_summary.candidate_socket_checks ?? 0);

  return (
    <>
      <section className="project-context">
        <div>
          <p className="section-index">NETWORK INVENTORY / POLICY FIRST</p>
          <h1>{project.name}</h1>
          <p>DNS 解析不等于 IP 所有权；分类、Scope 与 Profile 共同决定可扫描端口。</p>
        </div>
        <div className="inventory-nav">
          <Link className="button-secondary" href={`/projects/${projectId}/scope`}>Scope 与资产</Link>
          <Link className="button-secondary" href={`/projects/${projectId}/scans`}>任务中心</Link>
        </div>
      </section>

      {error ? <p className="form-error global-error" role="alert">{error}</p> : null}

      {latestPortJob?.status === "SKIPPED" ? <section className="enterprise-alert is-error" role="status">
        <strong>最近一次端口阶段未执行</strong>
        <p>{latestPortJob.error_code === "NO_POLICY_APPROVED_INPUTS" ? "没有 IP 通过当时的安全策略；新版本会让当前扫描中由已授权域名解析出的公网 IP 继承安全 Web 端口权限，同时继续拦截 CDN、私网与无来源 IP。" : latestPortJob.error_message}</p>
      </section> : null}

      {latestPortJob?.error_code === "PORT_SCAN_INTERCEPTION_SUSPECTED" ? <section className="enterprise-alert is-error" role="alert">
        <strong>端口结果已隔离：检测到代理/TUN 截获</strong>
        <p>本轮候选端口几乎全部返回开放，不符合可信的公网扫描分布。系统已删除本轮端口与派生服务资产；关闭全局透明代理后，可在任务中心单独重试端口阶段。</p>
      </section> : null}

      {ignoredMappings ? <section className="enterprise-alert" role="status">
        <strong>已保护真实目标视图</strong>
        <p>系统保留了 {ignoredMappings} 条历史代理映射用于审计，但不会再把它们显示为目标 IP、加入端口清单或用于主动扫描。下一次真实扫描会通过独立 DoH 补充公网地址。</p>
      </section> : null}

      {attackSurface ? <AttackSurfaceOverview projectId={projectId} data={attackSurface} /> : null}

      <details className="scope-panel execution-audit-panel">
        <summary>
          <div>
            <p className="section-index">EXECUTION AUDIT</p>
            <h2>端口扫描执行审计</h2>
            <p className="panel-note">下列数字用于判断端口阶段是否完整执行；域名结果请优先查看上方攻击面视图。</p>
          </div>
          <span>展开执行数据</span>
        </summary>
        <div className="inventory-summary execution-audit-summary">
          <div><span>可见 IP</span><strong>{ipTotal}</strong></div>
          <div><span>本轮扫描 IP</span><strong>{scanTargets}</strong></div>
          <div><span>每 IP 测试端口</span><strong>{testedPorts}</strong></div>
          <div><span>候选端口检查</span><strong>{candidateChecks.toLocaleString("zh-CN")}</strong></div>
          <div><span>开放端口记录</span><strong>{portTotal}</strong></div>
          <div><span>CDN / WAF</span><strong>{ips.filter((ip) => ip.classification === "CDN_WAF").length}</strong></div>
          <div><span>代理映射已隔离</span><strong>{ignoredMappings}</strong></div>
        </div>
      </details>

      {ips.length ? <details className="scope-panel inventory-classifier">
        <summary>
        <div>
          <p className="section-index">MANUAL CLASSIFICATION</p>
          <h2>人工分类与审计证据</h2>
          <p className="panel-note">只有处于 IN_SCOPE 的 IP 才能标记 OWNED；私网和保留地址不能解锁主动扫描。</p>
        </div>
        <span>展开分类</span>
        </summary>
        <form onSubmit={classify}>
          <select value={assetId} onChange={(event) => setAssetId(event.target.value)} required>
            {ips.map((ip) => <option key={ip.asset_id} value={ip.asset_id}>{ip.ip} · {ip.scope_status}</option>)}
          </select>
          <select value={classification} onChange={(event) => setClassification(event.target.value as IPClassification)}>
            {classifications.map((item) => <option key={item}>{item}</option>)}
          </select>
          <input value={reason} onChange={(event) => setReason(event.target.value)} placeholder="分类依据（将写入审计日志）" minLength={3} required />
          <button type="submit" disabled={saving || !ips.length}>{saving ? "正在保存" : "保存分类"}</button>
        </form>
      </details> : null}

      <section className="scope-panel asset-panel">
        <div className="panel-heading"><div><p className="section-index">IP POLICY</p><h2>IP 分类</h2></div><span className="guard-badge">CDN DEFAULT DENY</span></div>
        <div className="asset-table-wrap">
          <table className="asset-table">
            <thead><tr><th>IP</th><th>Scope</th><th>分类</th><th>来源</th><th>ASN / 组织</th></tr></thead>
            <tbody>{ips.length ? ips.map((ip) => (
              <tr key={ip.asset_id}>
                <td><code>{ip.ip}</code></td><td>{ip.scope_status}</td>
                <td><span className={`scope-state ip-${ip.classification.toLowerCase()}`}>{ip.classification}</span></td>
                <td>{ip.classification_source}</td><td>{ip.asn ?? "—"} {ip.organization ?? ip.provider ?? ""}</td>
              </tr>
            )) : <tr><td className="table-empty" colSpan={5}>尚无 IP 资产。</td></tr>}</tbody>
          </table>
        </div>
        {ipTotal > 100 ? <nav className="pagination-bar" aria-label="IP 分页">
          <button type="button" disabled={ipPage === 1} onClick={() => setIpPage((page) => Math.max(1, page - 1))}>上一页</button>
          <span>第 {ipPage} / {Math.ceil(ipTotal / 100)} 页 · 共 {ipTotal} 个 IP</span>
          <button type="button" disabled={ipPage >= Math.ceil(ipTotal / 100)} onClick={() => setIpPage((page) => page + 1)}>下一页</button>
        </nav> : null}
      </section>

      <section className="scope-panel asset-panel">
        <div className="panel-heading"><div><p className="section-index">PORTS & SERVICES</p><h2>端口与服务</h2></div><span className="guard-badge">NAABU OPEN + NMAP FINGERPRINT</span></div>
        <div className="asset-table-wrap">
          <table className="asset-table">
            <thead><tr><th>端点</th><th>状态</th><th>服务</th><th>产品 / 版本</th><th>最近发现</th></tr></thead>
            <tbody>{ports.length ? ports.map((item) => (
              <tr key={item.id}>
                <td><code>{item.ip}:{item.port}/{item.protocol}</code></td><td>{item.state}</td>
                <td>{item.service?.name ?? "未识别"}{item.service?.tls ? " · TLS" : ""}</td>
                <td>{[item.service?.product, item.service?.version].filter(Boolean).join(" ") || "—"}</td>
                <td>{new Date(item.last_seen_at).toLocaleString("zh-CN")}</td>
              </tr>
            )) : <tr><td className="table-empty" colSpan={5}>{latestPortJob?.status === "SUCCESS" ? `已完成 ${candidateChecks.toLocaleString("zh-CN")} 次候选端口检查，本轮没有发现开放端口。` : "尚无开放端口记录，或端口阶段未执行。"}</td></tr>}</tbody>
          </table>
        </div>
        {portTotal > 100 ? <nav className="pagination-bar" aria-label="端口分页">
          <button type="button" disabled={portPage === 1} onClick={() => setPortPage((page) => Math.max(1, page - 1))}>上一页</button>
          <span>第 {portPage} / {Math.ceil(portTotal / 100)} 页 · 共 {portTotal} 条端口记录</span>
          <button type="button" disabled={portPage >= Math.ceil(portTotal / 100)} onClick={() => setPortPage((page) => page + 1)}>下一页</button>
        </nav> : null}
      </section>
    </>
  );
}
