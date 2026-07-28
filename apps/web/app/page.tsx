import Link from "next/link";

import { AppHeader } from "@/components/projects/app-header";
import { StatusDashboard } from "@/components/status-dashboard";

const workflow = [
  { name: "企业识别", state: "当前可用" },
  { name: "Scope 确认", state: "当前可用" },
  { name: "扫描计划", state: "当前可用" },
  { name: "资产发现", state: "完整链路可用" },
  { name: "证据归并", state: "当前可用" },
];

export default function Home() {
  return (
    <main className="shell">
      <AppHeader />

      <section className="hero" id="main">
        <div className="hero-copy">
          <p className="eyebrow">LOCAL-FIRST / SCOPE-GATED / EVIDENCE-LED</p>
          <h1>
            先确认边界，
            <br />
            再发现攻击面。
          </h1>
          <p className="hero-intro">
            面向合法授权安全测试的本地资产发现平台。所有主动任务都必须经过 Scope
            双重校验；第三方、CDN/WAF 与未知资产不会被静默扩展扫描。
          </p>
          <div className="hero-actions">
            <Link className="button-primary" href="/projects/new">新建授权项目</Link>
            <Link className="button-secondary" href="/projects">查看项目</Link>
          </div>
        </div>

        <aside className="boundary-card" aria-label="安全边界">
          <div className="boundary-title">
            <span>安全边界</span>
            <span className="locked">LOCKED</span>
          </div>
          <div className="boundary-grid" aria-hidden="true">
            <span />
            <span />
            <span />
            <span />
          </div>
          <dl>
            <div>
              <dt>主动扫描</dt>
              <dd>显式授权</dd>
            </div>
            <div>
              <dt>已确认 Scope</dt>
              <dd>项目隔离</dd>
            </div>
            <div>
              <dt>外部工具调用</dt>
              <dd>版本门禁</dd>
            </div>
          </dl>
          <p>默认支持完全离线 fixture；端口、Nuclei 和外部工具执行均由后端再次独立校验。</p>
        </aside>
      </section>

      <StatusDashboard />

      <section className="workflow" aria-labelledby="workflow-title">
        <div>
          <p className="section-index">02 / PRODUCT GATE</p>
          <h2 id="workflow-title">平台工作流</h2>
        </div>
        <ol>
          {workflow.map((step, index) => (
            <li key={step.name} className={index === 2 ? "is-next" : undefined}>
              <span>{String(index + 1).padStart(2, "0")}</span>
              <strong>{step.name}</strong>
              <small>{step.state}</small>
            </li>
          ))}
        </ol>
      </section>

      <footer>
        <span>ScopeGraph v1.0.0</span>
        <span>数据默认仅保存在本机</span>
      </footer>
    </main>
  );
}
