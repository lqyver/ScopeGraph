import { AppHeader } from "@/components/projects/app-header";
import { WebsiteInventory } from "@/components/projects/website-inventory";

interface PageProps {
  params: Promise<{ id: string }>;
}

export default async function WebsitesPage({ params }: PageProps) {
  const { id } = await params;
  return <><AppHeader /><main className="shell page-shell"><WebsiteInventory projectId={id} /></main></>;
}
