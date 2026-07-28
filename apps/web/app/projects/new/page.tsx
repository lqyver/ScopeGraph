import type { Metadata } from "next";

import { AppHeader } from "@/components/projects/app-header";
import { NewProjectForm } from "@/components/projects/new-project-form";

export const metadata: Metadata = { title: "新建项目 · ScopeGraph" };

export default function NewProjectPage() {
  return (
    <main className="shell page-shell">
      <AppHeader />
      <section className="page-heading">
        <div>
          <p className="section-index">NEW AUTHORIZED PROJECT</p>
          <h1>建立资产边界</h1>
        </div>
        <p>这是授权记录，不是扫描按钮。</p>
      </section>
      <NewProjectForm />
    </main>
  );
}

