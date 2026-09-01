import type { Metadata } from "next";

import { AppHeader } from "@/components/projects/app-header";
import { evidenceModeFromParam } from "@/components/projects/evidence-mode";
import { ScopeManager } from "@/components/projects/scope-manager";

export const metadata: Metadata = { title: "Scope 与资产 · ScopeGraph" };

interface ScopePageProps {
  params: Promise<{ id: string }>;
  searchParams: Promise<{ execution_mode?: string | string[] }>;
}

export default async function ScopePage({ params, searchParams }: ScopePageProps) {
  const { id } = await params;
  const query = await searchParams;
  return (
    <main className="shell page-shell">
      <AppHeader />
      <ScopeManager projectId={id} initialMode={evidenceModeFromParam(query.execution_mode)} />
    </main>
  );
}

