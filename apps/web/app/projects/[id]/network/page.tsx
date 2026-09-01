import { AppHeader } from "@/components/projects/app-header";
import { NetworkInventory } from "@/components/projects/network-inventory";
import { evidenceModeFromParam } from "@/components/projects/evidence-mode";

interface PageProps {
  params: Promise<{ id: string }>;
  searchParams: Promise<{ execution_mode?: string | string[] }>;
}

export default async function NetworkPage({ params, searchParams }: PageProps) {
  const { id } = await params;
  const query = await searchParams;
  return (
    <>
      <AppHeader />
      <main className="shell page-shell">
        <NetworkInventory projectId={id} initialMode={evidenceModeFromParam(query.execution_mode)} />
      </main>
    </>
  );
}
