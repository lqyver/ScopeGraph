import { describe, expect, it } from "vitest";

import { ScanJob, ScanRun } from "./api";
import {
  adapterLabel,
  formatDuration,
  jobIssueText,
  jobResultLine,
  runExecutionPresentation,
  runResultLine,
  scanStatusLabel,
} from "./scan-utils";

const run = {
  status: "PARTIAL_SUCCESS",
  summary: { assets_created: 739, observations_created: 739 },
} as unknown as ScanRun;

const job = (status: ScanJob["status"], error_code: string | null = null) =>
  ({ status, error_code, error_message: null } as ScanJob);

describe("scan presentation helpers", () => {
  it("uses readable Chinese labels", () => {
    expect(scanStatusLabel("PARTIAL_SUCCESS")).toBe("部分完成");
    expect(adapterLabel("httpx")).toBe("网站可达性探测");
  });

  it("explains safe skips and partial results", () => {
    expect(jobIssueText(job("SKIPPED", "NO_POLICY_APPROVED_INPUTS"))).toContain("安全策略");
    expect(jobIssueText(job("PARTIAL_SUCCESS", "CRAWL_BUDGET_REACHED"))).toContain("已经保留");
    expect(jobIssueText(job("PARTIAL_SUCCESS", "SCREENSHOT_BUDGET_REACHED"))).toContain("截图");
    expect(jobIssueText(job("PARTIAL_SUCCESS", "ASSET_LIMIT_REACHED"))).toContain("资产上限");
    expect(
      jobIssueText(job("PARTIAL_SUCCESS", "PORT_SCAN_INTERCEPTION_SUSPECTED")),
    ).toContain("代理/TUN");
    expect(
      runResultLine(run, [job("SUCCESS"), job("PARTIAL_SUCCESS"), job("SKIPPED")]),
    ).toContain("739");
  });

  it("summarizes live and completed stage results", () => {
    expect(formatDuration(125)).toBe("2 分 5 秒");
    expect(jobResultLine({
      ...job("RUNNING"),
      result_summary: { input_count: 238 },
    })).toContain("238");
    expect(jobResultLine({
      ...job("SUCCESS"),
      result_summary: {
        input_count: 238,
        observations_parsed: 200,
        assets_created: 12,
        parser_skipped_invalid_endpoints: 4,
      },
    })).toContain("解析 200");
    expect(jobResultLine({
      ...job("SUCCESS"),
      result_summary: { parser_skipped_invalid_endpoints: 4 },
    })).toContain("隔离 4 条");
  });

  it("does not present a partially completed terminal run as a successful 100 percent scan", () => {
    const presentation = runExecutionPresentation(
      { ...run, progress: 100 } as ScanRun,
      [job("SUCCESS"), job("FAILED"), job("SKIPPED")],
    );

    expect(presentation.label).toBe("执行结果");
    expect(presentation.value).toBe("部分完成");
    expect(presentation.detail).toContain("100% 仅表示流程已结束");
    expect(presentation.showProgress).toBe(false);
  });
});
