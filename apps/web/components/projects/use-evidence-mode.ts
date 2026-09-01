"use client";

import { usePathname, useRouter } from "next/navigation";
import { useCallback } from "react";

import { evidenceModeQuery, type EvidenceMode } from "./evidence-mode";

export function useEvidenceMode(initialMode: EvidenceMode) {
  const pathname = usePathname();
  const router = useRouter();

  const updateMode = useCallback((nextMode: EvidenceMode) => {
    router.replace(`${pathname}${evidenceModeQuery(nextMode)}`, { scroll: false });
  }, [pathname, router]);

  return [initialMode, updateMode] as const;
}
