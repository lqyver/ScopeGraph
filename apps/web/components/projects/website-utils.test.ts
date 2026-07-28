import { describe, expect, it } from "vitest";

import type { WebsiteSummary } from "./api";
import { filterWebsites, websiteStats } from "./website-utils";

const base: WebsiteSummary = {
  id: "1",
  project_id: "project",
  asset_id: "asset",
  url: "https://www.example.com/",
  final_url: "https://www.example.com/",
  title: "Example Portal",
  status_code: 200,
  content_type: "text/html",
  ip: "93.184.216.34",
  port: 443,
  is_alive: true,
  scope_status: "IN_SCOPE",
  ownership_status: "CONFIRMED",
  icp_status: "PAGE_DIRECT",
  technologies: ["Next.js 15"],
  cdn_waf: ["Vercel"],
  screenshot_path: "capture.png",
  endpoint_count: 5,
  finding_count: 0,
  first_seen_at: "2026-07-16T00:00:00Z",
  last_seen_at: "2026-07-16T00:00:00Z",
};

describe("website inventory helpers", () => {
  it("searches titles, URLs, IPs and fingerprints", () => {
    expect(filterWebsites([base], "next.js")).toEqual([base]);
    expect(filterWebsites([base], "93.184")).toEqual([base]);
    expect(filterWebsites([base], "missing")).toEqual([]);
  });

  it("computes stable user-facing totals", () => {
    expect(websiteStats([base])).toEqual({
      alive: 1,
      directFilings: 1,
      screenshots: 1,
      technologies: 1,
    });
  });
});
