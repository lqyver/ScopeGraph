import { AppHeader } from "@/components/projects/app-header";
import { SecurityCenter } from "@/components/projects/security-center";
import { evidenceModeFromParam } from "@/components/projects/evidence-mode";

interface PageProps {
  params: Promise<{ id: string }>;
  searchParams: Promise<{ execution_mode?: string | string[] }>;
}

export default async function SecurityPage({ params, searchParams }: PageProps) {
  const { id } = await params;
  const query = await searchParams;
  return <><AppHeader /><main className="shell page-shell"><SecurityCenter projectId={id} initialMode={evidenceModeFromParam(query.execution_mode)} /></main></>;
}
