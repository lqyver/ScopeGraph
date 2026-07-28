import type { Metadata } from "next";

import { AppHeader } from "@/components/projects/app-header";
import { ScanCenter } from "@/components/projects/scan-center";

export const metadata: Metadata = { title: "扫描任务 · ScopeGraph" };

interface ScanPageProps {
  params: Promise<{ id: string }>;
}

export default async function ScanPage({ params }: ScanPageProps) {
  const { id } = await params;
  return (
    <main className="shell page-shell">
      <AppHeader />
      <ScanCenter projectId={id} />
    </main>
  );
}
