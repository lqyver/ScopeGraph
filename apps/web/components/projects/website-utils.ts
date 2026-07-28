import type { WebsiteSummary } from "./api";

export function filterWebsites(items: WebsiteSummary[], query: string): WebsiteSummary[] {
  const needle = query.trim().toLocaleLowerCase();
  if (!needle) return items;
  return items.filter((item) =>
    [item.url, item.final_url, item.title, item.ip, ...item.technologies, ...item.cdn_waf]
      .filter(Boolean)
      .some((value) => String(value).toLocaleLowerCase().includes(needle)),
  );
}

export function websiteStats(items: WebsiteSummary[]) {
  return {
    alive: items.filter((item) => item.is_alive).length,
    directFilings: items.filter((item) => item.icp_status === "PAGE_DIRECT").length,
    screenshots: items.filter((item) => item.screenshot_path !== null).length,
    technologies: new Set(items.flatMap((item) => item.technologies)).size,
  };
}
