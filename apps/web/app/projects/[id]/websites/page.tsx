import { AppHeader } from "@/components/projects/app-header";
import { evidenceModeFromParam } from "@/components/projects/evidence-mode";
import { WebsiteInventory } from "@/components/projects/website-inventory";

interface PageProps {
  params: Promise<{ id: string }>;
  searchParams: Promise<{ execution_mode?: string | string[] }>;
}

export default async function WebsitesPage({ params, searchParams }: PageProps) {
  const { id } = await params;
  const query = await searchParams;
  return <><AppHeader /><main className="shell page-shell"><WebsiteInventory projectId={id} initialMode={evidenceModeFromParam(query.execution_mode)} /></main></>;
}
