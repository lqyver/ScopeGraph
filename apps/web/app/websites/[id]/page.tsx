import { AppHeader } from "@/components/projects/app-header";
import { evidenceModeFromParam } from "@/components/projects/evidence-mode";
import { WebsiteDetailView } from "@/components/projects/website-detail";

interface PageProps {
  params: Promise<{ id: string }>;
  searchParams: Promise<{ execution_mode?: string | string[] }>;
}

export default async function WebsitePage({ params, searchParams }: PageProps) {
  const { id } = await params;
  const query = await searchParams;
  return <><AppHeader /><main className="shell page-shell"><WebsiteDetailView websiteId={id} initialMode={evidenceModeFromParam(query.execution_mode)} /></main></>;
}
