"use client";

import { useRouter } from "next/navigation";
import { FormEvent, useState } from "react";

import { apiRequest, errorMessage, Project } from "./api";

export function NewProjectForm() {
  const router = useRouter();
  const [name, setName] = useState("");
  const [company, setCompany] = useState("");
  const [rootDomain, setRootDomain] = useState("");
  const [profile, setProfile] = useState("standard");
  const [authorized, setAuthorized] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setSubmitting(true);
    setError(null);
    try {
      const project = await apiRequest<Project>("projects", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          name,
          company_name: company,
          default_scan_profile: profile,
          authorization_confirmed: authorized,
          known_root_domains: rootDomain.trim() ? [rootDomain.trim()] : [],
        }),
      });
      router.push(
        rootDomain.trim()
          ? `/projects/${project.id}/scans?created=1`
          : `/projects/${project.id}/enterprise?created=1`,
      );
    } catch (caught) {
      setError(errorMessage(caught));
      setSubmitting(false);
    }
  }

  return (
    <form className="project-form" onSubmit={submit}>
      <div className="form-section">
        <span className="form-step">01</span>
        <div>
          <h2>项目与企业</h2>
          <p>项目名称只用于本地管理，企业名称用于后续归属分析。</p>
        </div>
      </div>
      <label>
        <span>项目名称</span>
        <input value={name} onChange={(event) => setName(event.target.value)} maxLength={200} required />
      </label>
      <label>
        <span>企业名称</span>
        <input
          value={company}
          onChange={(event) => setCompany(event.target.value)}
          maxLength={300}
          required
        />
      </label>

      <div className="form-section">
        <span className="form-step">02</span>
        <div>
          <h2>初始边界</h2>
          <p>根域名可稍后补充。即使填写，创建项目也不会立即扫描。</p>
        </div>
      </div>
      <label>
        <span>已确认根域名（可选）</span>
        <input
          value={rootDomain}
          onChange={(event) => setRootDomain(event.target.value)}
          placeholder="example.com"
          autoCapitalize="none"
          spellCheck={false}
        />
        <small>只填根域，例如 `example.com`；不要填写企业名称、`www` 子域或完整网址。</small>
      </label>
      <label>
        <span>默认扫描模式</span>
        <select value={profile} onChange={(event) => setProfile(event.target.value)}>
          <option value="quick">快速</option>
          <option value="standard">标准（推荐）</option>
          <option value="deep">深度</option>
          <option value="custom">自定义</option>
        </select>
      </label>

      <label className="authorization-box">
        <input
          type="checkbox"
          checked={authorized}
          onChange={(event) => setAuthorized(event.target.checked)}
          required
        />
        <span>
          <strong>我确认已获得对目标进行安全测试和资产发现的合法授权。</strong>
          <small>确认时间会写入项目记录和审计日志。</small>
        </span>
      </label>

      {error ? <p className="form-error" role="alert">{error}</p> : null}
      <button className="button-primary submit-button" type="submit" disabled={submitting || !authorized}>
        {submitting ? "正在创建…" : rootDomain.trim() ? "创建并配置首轮扫描" : "创建并发现企业根域"}
      </button>
    </form>
  );
}
