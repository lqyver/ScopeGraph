import type { Metadata } from "next";

import { AppHeader } from "@/components/projects/app-header";
import { ScopeManager } from "@/components/projects/scope-manager";

export const metadata: Metadata = { title: "Scope 与资产 · ScopeGraph" };

interface ScopePageProps {
  params: Promise<{ id: string }>;
}

export default async function ScopePage({ params }: ScopePageProps) {
  const { id } = await params;
  return (
    <main className="shell page-shell">
      <AppHeader />
      <ScopeManager projectId={id} />
    </main>
  );
}

