const REPO_URL = "https://github.com/RaunitChatterjee/MCP-Security-Auditor-Defense-Gateway";

export default function TopNav() {
  return (
    <header className="topnav">
      <div className="wrap">
        <div className="brand-mark">
          <span className="dot" />
          MCP Security Auditor
        </div>
        <div className="topnav-links">
          <nav>
            <a href="#live-attack">Live demo</a>
            <a href="#findings">Findings</a>
            <a href="#activity">Gateway activity</a>
            <a href="#vuln-classes">Vuln classes</a>
          </nav>
          <a className="gh-btn" href={REPO_URL} target="_blank" rel="noreferrer">
            GitHub
          </a>
        </div>
      </div>
    </header>
  );
}
