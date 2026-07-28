import { AppHeader } from "@/components/projects/app-header";
import { EnterpriseCenter } from "@/components/projects/enterprise-center";

interface PageProps {
  params: Promise<{ id: string }>;
}

export default async function EnterprisePage({ params }: PageProps) {
  const { id } = await params;
  return (
    <>
      <AppHeader />
      <main className="shell page-shell">
        <EnterpriseCenter projectId={id} />
      </main>
    </>
  );
}
