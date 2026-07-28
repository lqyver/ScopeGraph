"use client";

import { useCallback, useEffect, useState } from "react";

import { formatLatency, HealthReport, isHealthReport } from "./health";

const labels: Record<string, string> = {
  api: "API",
  database: "PostgreSQL",
  redis: "Redis Queue",
  storage: "本地存储",
};

export function StatusDashboard() {
  const [report, setReport] = useState<HealthReport | null>(null);
  const [loading, setLoading] = useState(true);
  const [message, setMessage] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    try {
      const response = await fetch("/api/health", { cache: "no-store" });
      const data: unknown = await response.json();
      if (!isHealthReport(data)) throw new Error("健康状态格式无效");
      setReport(data);
      setMessage(response.ok ? null : "核心服务尚未全部就绪");
    } catch {
      setMessage("暂时无法连接本地 API");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    const initial = window.setTimeout(() => void refresh(), 0);
    const timer = window.setInterval(() => void refresh(), 15_000);
    return () => {
      window.clearTimeout(initial);
      window.clearInterval(timer);
    };
  }, [refresh]);

  return (
    <section className="runtime" aria-labelledby="runtime-title" aria-live="polite">
      <div className="section-heading">
        <div>
          <p className="section-index">01 / RUNTIME STATUS</p>
          <h2 id="runtime-title">本地运行状态</h2>
        </div>
        <button type="button" onClick={() => void refresh()} disabled={loading}>
          {loading ? "检查中…" : "重新检查"}
        </button>
      </div>

      {message ? <p className="status-message">{message}</p> : null}

      <div className="status-grid">
        {Object.entries(labels).map(([key, label]) => {
          const check = report?.checks[key];
          const healthy = check?.status === "healthy";
          return (
            <article className="status-card" key={key}>
              <div>
                <span className={`status-light ${healthy ? "is-healthy" : ""}`} />
                <span>{label}</span>
              </div>
              <strong>{loading && !check ? "检查中" : healthy ? "正常" : "未就绪"}</strong>
              <small>{formatLatency(check?.latency_ms)}</small>
            </article>
          );
        })}
      </div>

      <div className="metric-split">
        <div>
          <span>任务执行完成度</span>
          <strong>—</strong>
          <small>尚未创建扫描任务</small>
        </div>
        <div>
          <span>攻击面覆盖置信度</span>
          <strong>未评估</strong>
          <small>不等同于任务完成度</small>
        </div>
      </div>
    </section>
  );
}
