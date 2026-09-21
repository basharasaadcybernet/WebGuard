import { Icon } from "./Icon";

export function AppHeader() {
  return (
    <header className="site-header">
      <a className="brand" href="#top" aria-label="Bashar Asaad WebGuard home">
        <img src="/brand/logo.svg" width="42" height="42" alt="" />
        <span className="brand-copy">
          <strong>Bashar Asaad</strong>
          <span>WebGuard</span>
        </span>
      </a>
      <nav className="header-nav" aria-label="Primary navigation">
        <a href="#coverage">What we assess</a>
        <a href="#scan" className="header-action">
          <Icon name="scan" />
          Start a scan
        </a>
      </nav>
    </header>
  );
}
