import { describe, expect, it } from "vitest";

import { evidenceModeFromParam, evidenceModeQuery } from "./evidence-mode";

describe("evidence mode navigation", () => {
  it("accepts only the explicit fixture query value", () => {
    expect(evidenceModeFromParam("fixture")).toBe("fixture");
    expect(evidenceModeFromParam(["fixture", "host"])).toBe("fixture");
    expect(evidenceModeFromParam("host")).toBe("host");
    expect(evidenceModeFromParam("unexpected")).toBe("host");
    expect(evidenceModeFromParam(undefined)).toBe("host");
  });

  it("keeps real results as the clean default URL", () => {
    expect(evidenceModeQuery("fixture")).toBe("?execution_mode=fixture");
    expect(evidenceModeQuery("host")).toBe("");
    expect(evidenceModeQuery(undefined)).toBe("");
  });
});
