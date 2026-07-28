import { describe, expect, it } from "vitest";

import { projectDeleteConfirmationMatches } from "./project-utils";

describe("project deletion confirmation", () => {
  it("requires the exact project name", () => {
    expect(projectDeleteConfirmationMatches("示例公网资产", "示例公网资产")).toBe(true);
    expect(projectDeleteConfirmationMatches("示例公网资产", "示例")).toBe(false);
    expect(projectDeleteConfirmationMatches("示例公网资产", "示例公网资产 ")).toBe(false);
  });
});
