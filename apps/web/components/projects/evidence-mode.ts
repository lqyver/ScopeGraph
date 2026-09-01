export type EvidenceMode = "host" | "fixture";

export function evidenceModeFromParam(value: string | string[] | undefined): EvidenceMode {
  const selected = Array.isArray(value) ? value[0] : value;
  return selected === "fixture" ? "fixture" : "host";
}

export function evidenceModeQuery(mode: EvidenceMode | undefined): string {
  return mode === "fixture" ? "?execution_mode=fixture" : "";
}
