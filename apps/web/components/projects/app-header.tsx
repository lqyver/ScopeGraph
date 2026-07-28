import Link from "next/link";

export function AppHeader() {
  return (
    <header className="topbar">
      <Link className="brand" href="/" aria-label="ScopeGraph 首页">
        <span className="brand-mark" aria-hidden="true">
          SG
        </span>
        <span>
          <strong>ScopeGraph</strong>
          <small>PUBLIC ATTACK SURFACE</small>
        </span>
      </Link>
      <nav className="main-nav" aria-label="主导航">
        <Link href="/projects">项目</Link>
        <Link href="/system">系统</Link>
        <Link className="nav-primary" href="/projects/new">
          新建项目
        </Link>
      </nav>
    </header>
  );
}
