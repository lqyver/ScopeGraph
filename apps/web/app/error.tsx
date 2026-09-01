"use client";

export default function Error({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  return (
    <main className="shell">
      <section className="error-panel" role="alert">
        <p className="eyebrow">SCOPEGRAPH / RECOVERABLE ERROR</p>
        <strong>页面暂时无法读取本地 API</strong>
        <p>{error.message || "请检查 API 服务状态后重试。"}</p>
        <button type="button" onClick={() => reset()}>
          重试
        </button>
      </section>
    </main>
  );
}
