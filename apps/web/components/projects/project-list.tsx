"use client";

import Link from "next/link";
import { useCallback, useEffect, useState } from "react";

import { apiRequest, errorMessage, ProjectPage } from "./api";
import { projectDeleteConfirmationMatches } from "./project-utils";

const profileLabels = {
  quick: "快速",
  standard: "标准",
  deep: "深度",
  custom: "自定义",
};

export function ProjectList() {
  const [data, setData] = useState<ProjectPage | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [deleteTarget, setDeleteTarget] = useState<ProjectPage["items"][number] | null>(null);
  const [deleteConfirmation, setDeleteConfirmation] = useState("");
  const [deleting, setDeleting] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      setError(null);
      setData(await apiRequest<ProjectPage>("projects"));
    } catch (caught) {
      setError(errorMessage(caught));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    const initial = window.setTimeout(() => void load(), 0);
    return () => window.clearTimeout(initial);
  }, [load]);

  function requestDelete(project: ProjectPage["items"][number]) {
    setDeleteTarget(project);
    setDeleteConfirmation("");
    setActionError(null);
    setNotice(null);
  }

  function closeDeleteDialog() {
    if (deleting) return;
    setDeleteTarget(null);
    setDeleteConfirmation("");
    setActionError(null);
  }

  async function confirmDelete() {
    if (
      !deleteTarget
      || !projectDeleteConfirmationMatches(deleteTarget.name, deleteConfirmation)
    ) return;
    try {
      setDeleting(true);
      setActionError(null);
      await apiRequest<void>(`projects/${deleteTarget.id}`, {
        method: "DELETE",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ confirmation: deleteConfirmation }),
      });
      const deletedName = deleteTarget.name;
      setDeleteTarget(null);
      setDeleteConfirmation("");
      setNotice(`项目“${deletedName}”已删除。扫描记录和证据已软删除保留。`);
      await load();
    } catch (caught) {
      setActionError(errorMessage(caught));
    } finally {
      setDeleting(false);
    }
  }

  if (loading) return <div className="loading-panel">正在读取本地项目…</div>;
  if (error)
    return (
      <div className="error-panel" role="alert">
        <strong>项目读取失败</strong>
        <p>{error}</p>
        <button type="button" onClick={() => void load()}>
          重试
        </button>
      </div>
    );
  if (!data?.items.length)
    return (
      <>
        {notice ? <div className="enterprise-alert" role="status">{notice}</div> : null}
        <div className="empty-state">
          <span>NO PROJECTS</span>
          <h2>先建立授权边界，再开始资产发现。</h2>
          <p>创建项目不会自动扫描；必须至少确认一个根域名后，后续阶段才允许主动任务。</p>
          <Link className="button-primary" href="/projects/new">
            创建第一个项目
          </Link>
        </div>
      </>
    );

  return (
    <>
      {notice ? <div className="enterprise-alert" role="status">{notice}</div> : null}
      <div className="project-grid">
        {data.items.map((project) => (
          <article className="project-card" key={project.id}>
            <div className="project-card-top">
              <span className={`project-status status-${project.status.toLowerCase()}`}>
                {project.status}
              </span>
              <span>{profileLabels[project.default_scan_profile]}</span>
            </div>
            <h2>{project.name}</h2>
            <p>{project.company_name}</p>
            <dl>
              <div>
                <dt>授权确认</dt>
                <dd>{new Date(project.authorization_confirmed_at).toLocaleDateString("zh-CN")}</dd>
              </div>
              <div>
                <dt>更新时间</dt>
                <dd>{new Date(project.updated_at).toLocaleString("zh-CN")}</dd>
              </div>
            </dl>
            <div className="project-card-links">
              <Link className="button-primary" href={`/projects/${project.id}/scans`}>打开项目工作台</Link>
              <Link href={`/projects/${project.id}/websites`}>网站结果</Link>
              <Link href={`/projects/${project.id}/scope`}>资产</Link>
              <Link href={`/projects/${project.id}/security`}>安全与导出</Link>
              <button
                className="danger-action project-delete-trigger"
                type="button"
                onClick={() => requestDelete(project)}
                aria-label={`删除项目 ${project.name}`}
              >
                删除项目
              </button>
            </div>
          </article>
        ))}
      </div>

      {deleteTarget ? (
        <div
          className="project-delete-backdrop"
          onMouseDown={(event) => {
            if (event.target === event.currentTarget) closeDeleteDialog();
          }}
        >
          <section
            className="project-delete-dialog"
            role="dialog"
            aria-modal="true"
            aria-labelledby="project-delete-title"
          >
            <p className="eyebrow">SOFT DELETE / SECOND CONFIRMATION</p>
            <h2 id="project-delete-title">删除项目“{deleteTarget.name}”？</h2>
            <p>
              项目会立即从工作区隐藏，未结束的扫描将收到取消请求。数据库记录和证据文件暂时保留，不会执行永久清理。
            </p>
            <label htmlFor="project-delete-confirmation">
              输入项目名称 <strong>{deleteTarget.name}</strong> 以确认
            </label>
            <input
              id="project-delete-confirmation"
              autoFocus
              value={deleteConfirmation}
              disabled={deleting}
              onChange={(event) => setDeleteConfirmation(event.target.value)}
              onKeyDown={(event) => {
                if (event.key === "Escape") closeDeleteDialog();
                if (event.key === "Enter") void confirmDelete();
              }}
              autoComplete="off"
            />
            {actionError ? <div className="form-error" role="alert">{actionError}</div> : null}
            <div className="project-delete-actions">
              <button type="button" disabled={deleting} onClick={closeDeleteDialog}>取消</button>
              <button
                className="danger-action"
                type="button"
                disabled={
                  deleting
                  || !projectDeleteConfirmationMatches(deleteTarget.name, deleteConfirmation)
                }
                onClick={() => void confirmDelete()}
              >
                {deleting ? "正在删除…" : "确认删除项目"}
              </button>
            </div>
          </section>
        </div>
      ) : null}
    </>
  );
}
