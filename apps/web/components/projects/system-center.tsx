"use client";

import { FormEvent, useCallback, useEffect, useState } from "react";

import { apiRequest, errorMessage, StorageStatus, SystemSettings, ToolStatus } from "./api";

export function SystemCenter() {
  const [tools, setTools] = useState<ToolStatus[]>([]);
  const [settings, setSettings] = useState<SystemSettings | null>(null);
  const [storage, setStorage] = useState<StorageStatus | null>(null);
  const [proxy, setProxy] = useState("");
  const [loading, setLoading] = useState(true);
  const [working, setWorking] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const [toolData, settingData, storageData] = await Promise.all([
        apiRequest<ToolStatus[]>("system/tools"),
        apiRequest<SystemSettings>("system/settings"),
        apiRequest<StorageStatus>("system/storage"),
      ]);
      setTools(toolData); setSettings(settingData); setStorage(storageData);
      setProxy(settingData.proxy_url ?? ""); setError(null);
    } catch (caught) { setError(errorMessage(caught)); }
    finally { setLoading(false); }
  }, []);

  useEffect(() => { const timer = window.setTimeout(() => void load(), 0); return () => window.clearTimeout(timer); }, [load]);

  async function saveSettings(event: FormEvent) {
    event.preventDefault(); setWorking(true); setError(null);
    try {
      const updated = await apiRequest<SystemSettings>("system/settings", {
        method: "PATCH", headers: { "content-type": "application/json" },
        body: JSON.stringify({ proxy_url: proxy || null }),
      });
      setSettings(updated); setNotice("代理默认值已保存；新扫描仍会在创建前明确展示并校验。");
    } catch (caught) { setError(errorMessage(caught)); }
    finally { setWorking(false); }
  }

  async function checkTool(name: string) {
    setWorking(true); setError(null);
    try {
      const result = await apiRequest<ToolStatus>(`system/tools/${name}/check-update`, { method: "POST" });
      setTools((current) => current.map((item) => item.name === name ? result : item));
      setNotice(`${name} 已重新检测；ScopeGraph 未执行任何自动更新。`);
    } catch (caught) { setError(errorMessage(caught)); }
    finally { setWorking(false); }
  }

  if (loading) return <div className="loading-panel">正在检测系统运行环境…</div>;
  const editionLabel = settings?.edition?.toUpperCase() ?? "UNKNOWN";
  const editionDetail = settings?.edition === "internal"
    ? "内部开发与授权环境"
    : settings?.edition === "community"
      ? "Apache-2.0 社区版本"
      : "无法读取运行版本";
  return <>
    <header className="system-heading"><p className="eyebrow">PHASE 7 / RELEASE CONTROL</p><h1>系统兼容性与发布门禁</h1><p>版本不兼容会阻止执行；工具永不静默更新；非回环监听必须配置 API Key。</p></header>
    {error && <div className="enterprise-alert is-error" role="alert">{error}</div>}
    {notice && <div className="enterprise-alert" role="status">{notice}</div>}
    <section className="system-summary"><article><span>运行版本</span><strong>{editionLabel}</strong><small>{editionDetail}</small></article><article><span>工具适配器</span><strong>{tools.length}</strong><small>{tools.filter((item) => item.compatible).length} 个当前兼容</small></article><article><span>文件存储</span><strong>{((storage?.total_bytes ?? 0) / 1024 / 1024).toFixed(1)} MiB</strong><small>{storage?.file_count ?? 0} 个文件</small></article><article><span>公开监听</span><strong>{settings?.public_bind ? "ENABLED" : "LOOPBACK"}</strong><small>{settings?.public_bind ? (settings.api_key_configured ? "API Key 已配置" : "缺少 API Key") : "Docker 端口仅发布到 127.0.0.1"}</small></article></section>
    <section className="tool-grid">{tools.map((tool) => <article key={tool.name}><header><strong>{tool.name}</strong><span className={tool.compatible ? "is-compatible" : ""}>{tool.compatible ? "COMPATIBLE" : tool.installed ? "BLOCKED" : "NOT INSTALLED"}</span></header><p>{tool.category}</p><code>{tool.version_output || tool.error || "未检测到版本"}</code><small>最低版本：{tool.minimum_version ?? "按输出标记兼容"}</small><button disabled={working} onClick={() => void checkTool(tool.name)}>重新检测</button></article>)}</section>
    <form className="proxy-settings" onSubmit={(event) => void saveSettings(event)}><div><p className="section-index">OUTBOUND PROXY / BURP</p><h2>Web 工具代理默认值</h2><p>只接受 HTTP(S) 主机与端口；禁止 URL 内嵌账号密码、路径、查询参数。</p></div><input value={proxy} onChange={(event) => setProxy(event.target.value)} placeholder="http://127.0.0.1:8080" /><button disabled={working}>保存设置</button></form>
  </>;
}
