import { ScanJob, ScanRun, ScanStatus } from "./api";

const STATUS_LABELS: Record<ScanStatus, string> = {
  PENDING: "等待中",
  QUEUED: "已排队",
  RUNNING: "执行中",
  PAUSED: "已暂停",
  PARTIAL_SUCCESS: "部分完成",
  SUCCESS: "已完成",
  FAILED: "失败",
  TIMEOUT: "超时",
  CANCELLED: "已取消",
  SKIPPED: "安全跳过",
};

const ADAPTER_LABELS: Record<string, string> = {
  subfinder: "被动子域发现",
  alterx: "域名变体生成",
  puredns: "域名有效性验证",
  dnsx: "DNS 解析与记录补充",
  naabu: "端口发现",
  nmap: "服务识别",
  httpx: "网站可达性探测",
  screenshot: "网站截图",
  katana: "网页与接口发现",
  nuclei: "低风险安全检查",
};

const TERMINAL_STATUSES = new Set<ScanStatus>([
  "SUCCESS",
  "PARTIAL_SUCCESS",
  "FAILED",
  "TIMEOUT",
  "CANCELLED",
  "SKIPPED",
]);

export function scanStatusLabel(status: ScanStatus): string {
  return STATUS_LABELS[status];
}

export function adapterLabel(name: string): string {
  return ADAPTER_LABELS[name] ?? name;
}

export function jobIssueText(job: ScanJob): string | null {
  if (job.error_code === "CRAWL_BUDGET_REACHED") {
    return "网页发现已达到本次时间预算；预算前产生的有效结果已经保留。";
  }
  if (job.error_code === "SCREENSHOT_BUDGET_REACHED") {
    return "截图已达到本次时间预算；已完成的截图和失败记录均已保留。";
  }
  if (job.error_code === "SECURITY_SCAN_BUDGET_REACHED") {
    return "安全检查已达到本次时间预算；预算前产生的完整命中已入库，仍需人工验证。";
  }
  if (job.error_code === "ASSET_LIMIT_REACHED") {
    return "已达到当前 Profile 的资产上限；既有资产证据已保留，新增资产已安全截断。";
  }
  if (job.error_code === "NO_POLICY_APPROVED_INPUTS") {
    return "没有通过安全策略的目标，系统已跳过主动探测；已有发现仍然保留。";
  }
  if (job.error_code === "PORT_SCAN_INTERCEPTION_SUSPECTED") {
    return "候选端口几乎全部返回开放，符合全局代理/TUN 截获特征；本批结果已隔离，不会作为目标真实端口展示。关闭透明代理后可单独重试端口阶段。";
  }
  if (job.error_code === "OUTPUT_PARSE_ERROR") {
    return "工具有部分输出无法解析；已保留其他有效结果，可重试此阶段。";
  }
  if (job.error_code === "TOOL_EXIT_NONZERO") {
    return "扫描工具运行异常；修复环境后可单独重试此阶段。";
  }
  if (job.error_code === "INPUT_VALIDATION_FAILED") {
    return "本阶段输入未通过安全校验，系统已隔离该阶段并继续后续流程。";
  }
  if (job.error_code === "STAGE_EXECUTION_FAILED") {
    return "本阶段发生内部异常，系统已记录原因并继续后续可执行阶段。";
  }
  if (job.status === "SKIPPED") return "该阶段因安全策略或缺少有效输入而跳过。";
  if (job.error_message) return job.error_message;
  return null;
}

export function formatDuration(totalSeconds: number): string {
  const seconds = Math.max(0, Math.floor(totalSeconds));
  if (seconds < 60) return `${seconds} 秒`;
  const minutes = Math.floor(seconds / 60);
  const remainder = seconds % 60;
  return remainder ? `${minutes} 分 ${remainder} 秒` : `${minutes} 分钟`;
}

export function jobElapsed(job: ScanJob, now: number): string {
  if (!job.started_at) return "尚未开始";
  const end = job.finished_at ? Date.parse(job.finished_at) : now;
  return formatDuration((end - Date.parse(job.started_at)) / 1000);
}

export function jobResultLine(job: ScanJob): string {
  const inputCount = Number(job.result_summary.input_count ?? 0);
  const observations = Number(job.result_summary.observations_parsed ?? 0);
  const assets = Number(job.result_summary.assets_created ?? 0);
  const skippedInvalidEndpoints = Number(
    job.result_summary.parser_skipped_invalid_endpoints ?? 0,
  );
  const liveBytes = Number(job.result_summary.live_output_bytes ?? 0);
  if (job.status === "RUNNING") {
    const output = liveBytes > 0 ? `，已实时写入 ${liveBytes.toLocaleString("zh-CN")} 字节结果` : "";
    return inputCount > 0 ? `正在处理 ${inputCount.toLocaleString("zh-CN")} 个目标${output}` : "正在准备安全输入";
  }
  if (job.status === "QUEUED") return "任务已入队，等待 worker 接收";
  if (job.status === "PENDING") return "等待前一阶段完成";
  if (job.status === "SUCCESS" || job.status === "PARTIAL_SUCCESS") {
    const isolated = skippedInvalidEndpoints > 0
      ? `，隔离 ${skippedInvalidEndpoints.toLocaleString("zh-CN")} 条非 HTTP(S) 端点`
      : "";
    const filingRecords = Number(job.result_summary.filing_records_found ?? 0);
    const pendingRedirects = Number(job.result_summary.cross_host_redirects ?? 0);
    const filing = job.adapter_name === "httpx"
      ? `，备案 ${filingRecords.toLocaleString("zh-CN")} 条${pendingRedirects ? `，${pendingRedirects.toLocaleString("zh-CN")} 个跨域跳转待核验` : ""}`
      : "";
    const findings = job.adapter_name === "nuclei"
      ? `，${job.result_summary.scan_strategy === "automatic" ? "按技术选模" : "宽模板"}命中 ${observations.toLocaleString("zh-CN")} 条（未验证）`
      : "";
    if (job.adapter_name === "naabu") {
      const targets = Number(job.result_summary.scan_targets ?? inputCount);
      const ports = Number(job.result_summary.ports_tested_per_target ?? 0);
      const checks = Number(job.result_summary.candidate_socket_checks ?? targets * ports);
      return `扫描 ${targets.toLocaleString("zh-CN")} 个 IP × ${ports.toLocaleString("zh-CN")} 个候选端口（${checks.toLocaleString("zh-CN")} 次端口检查），发现 ${observations.toLocaleString("zh-CN")} 个开放端口`;
    }
    return `处理 ${inputCount.toLocaleString("zh-CN")} 个目标，解析 ${observations.toLocaleString("zh-CN")} 条结果，新增 ${assets.toLocaleString("zh-CN")} 项资产${filing}${findings}${isolated}`;
  }
  return jobIssueText(job) ?? "等待前序阶段完成";
}

export function runResultLine(run: ScanRun, jobs: ScanJob[]): string {
  const assets = Number(run.summary.assets_created ?? 0);
  const observations = Number(run.summary.observations_created ?? 0);
  const succeeded = jobs.filter((job) => job.status === "SUCCESS").length;
  const affected = jobs.filter((job) =>
    ["FAILED", "TIMEOUT", "PARTIAL_SUCCESS"].includes(job.status),
  ).length;
  const skipped = jobs.filter((job) => job.status === "SKIPPED").length;
  const saved = Number(run.summary.parallel_time_saved_seconds ?? 0);
  const efficiency = saved >= 1 ? ` 并行编排减少约 ${formatDuration(saved)} 的顺序等待。` : "";
  const base = `已记录 ${assets.toLocaleString("zh-CN")} 项资产变化和 ${observations.toLocaleString("zh-CN")} 条观测。${efficiency}`;
  if (run.status === "SUCCESS") return `${base} ${succeeded} 个阶段全部完成。`;
  if (run.status === "PARTIAL_SUCCESS") {
    return `${base} ${succeeded} 个阶段完成，${affected} 个阶段异常，${skipped} 个阶段被安全跳过。`;
  }
  return base;
}

export function runExecutionPresentation(
  run: ScanRun,
  jobs: ScanJob[],
): { label: string; value: string; detail: string; showProgress: boolean } {
  const settled = jobs.filter((job) => TERMINAL_STATUSES.has(job.status)).length;
  const total = jobs.length;
  const stageCount = total ? `${settled}/${total} 个阶段` : "阶段";

  if (!TERMINAL_STATUSES.has(run.status)) {
    return {
      label: "执行进度",
      value: `${run.progress.toFixed(0)}%`,
      detail: `${stageCount} 已结算`,
      showProgress: true,
    };
  }

  if (run.status === "SUCCESS") {
    return {
      label: "执行结果",
      value: "已完成",
      detail: `${stageCount} 已全部成功结算`,
      showProgress: false,
    };
  }

  if (run.status === "PARTIAL_SUCCESS") {
    const failed = jobs.filter((job) => (
      ["FAILED", "TIMEOUT", "PARTIAL_SUCCESS"].includes(job.status)
    )).length;
    const skipped = jobs.filter((job) => job.status === "SKIPPED").length;
    return {
      label: "执行结果",
      value: "部分完成",
      detail: `${stageCount} 已结算，其中 ${failed} 个阶段异常、${skipped} 个安全跳过；100% 仅表示流程已结束。`,
      showProgress: false,
    };
  }

  const terminalNote = run.progress >= 100
    ? "100% 仅表示流程已结束，不代表扫描成功。"
    : "流程已结束，不代表扫描成功。";
  return {
    label: "执行结果",
    value: scanStatusLabel(run.status),
    detail: `${stageCount} 已结算；${terminalNote}`,
    showProgress: false,
  };
}
