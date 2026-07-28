import { AppHeader } from "@/components/projects/app-header";
import { SecurityCenter } from "@/components/projects/security-center";

interface PageProps {
  params: Promise<{ id: string }>;
}

export default async function SecurityPage({ params }: PageProps) {
  const { id } = await params;
  return <><AppHeader /><main className="shell page-shell"><SecurityCenter projectId={id} /></main></>;
}
