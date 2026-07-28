import { AppHeader } from "@/components/projects/app-header";
import { WebsiteDetailView } from "@/components/projects/website-detail";

interface PageProps {
  params: Promise<{ id: string }>;
}

export default async function WebsitePage({ params }: PageProps) {
  const { id } = await params;
  return <><AppHeader /><main className="shell page-shell"><WebsiteDetailView websiteId={id} /></main></>;
}
