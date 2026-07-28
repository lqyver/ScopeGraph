import { AppHeader } from "@/components/projects/app-header";
import { NetworkInventory } from "@/components/projects/network-inventory";

interface PageProps {
  params: Promise<{ id: string }>;
}

export default async function NetworkPage({ params }: PageProps) {
  const { id } = await params;
  return (
    <>
      <AppHeader />
      <main className="shell page-shell">
        <NetworkInventory projectId={id} />
      </main>
    </>
  );
}
