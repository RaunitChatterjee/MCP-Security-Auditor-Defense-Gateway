const REPO_URL = "https://github.com/RaunitChatterjee/MCP-Security-Auditor-Defense-Gateway";

export default function Footer() {
  return (
    <footer className="site-footer">
      <div className="wrap">
        <span>MCP Security Auditor &amp; Defense Gateway — built Oct 2026</span>
        <div className="stack-badges">
          <span>Python</span>
          <span>FastAPI</span>
          <span>React</span>
        </div>
        <a href={REPO_URL} target="_blank" rel="noreferrer">
          View on GitHub
        </a>
      </div>
    </footer>
  );
}
