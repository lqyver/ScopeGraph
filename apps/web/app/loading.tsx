export default function Loading() {
  return (
    <main className="shell" aria-busy="true" aria-live="polite">
      <section className="loading-panel">
        <p className="eyebrow">SCOPEGRAPH / LOADING</p>
        <h1>正在加载项目证据…</h1>
        <p>页面数据仍在从本地 API 读取，当前不会触发新的扫描。</p>
      </section>
    </main>
  );
}
