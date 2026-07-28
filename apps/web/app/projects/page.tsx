import type { Metadata } from "next";

import { AppHeader } from "@/components/projects/app-header";
import { ProjectList } from "@/components/projects/project-list";

export const metadata: Metadata = { title: "项目 · ScopeGraph" };

export default function ProjectsPage() {
  return (
    <main className="shell page-shell">
      <AppHeader />
      <section className="page-heading">
        <div>
          <p className="section-index">PROJECT CONTROL</p>
          <h1>授权项目</h1>
        </div>
        <p>项目是 Scope、证据、资产和历史记录的隔离边界。</p>
      </section>
      <ProjectList />
    </main>
  );
}

