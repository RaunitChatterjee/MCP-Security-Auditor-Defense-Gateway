const CLASSES = [
  {
    code: "01",
    title: "Command injection",
    detail: "A tool argument reaches a shell unsanitized — crafted input runs arbitrary commands on the server.",
    owasp: "Insecure Plugin Design",
  },
  {
    code: "02",
    title: "Path traversal",
    detail: "A file tool doesn't check that the path it's given stays inside its own folder — it can read anything on disk.",
    owasp: "Insecure Plugin Design",
  },
  {
    code: "03",
    title: "Missing authentication",
    detail: "No login or token check at all — anyone who can reach the server can call any tool, including destructive ones.",
    owasp: "Excessive Agency",
  },
  {
    code: "04",
    title: "Over-permissioned tools",
    detail: "A tool built for one narrow task quietly accepts a parameter that lets it do far more than it should.",
    owasp: "Excessive Agency",
  },
  {
    code: "05",
    title: "Sequence-level exfiltration",
    detail: "Several individually-fine calls, chained together, add up to a data leak. No single call looks suspicious.",
    owasp: "Excessive Agency",
  },
];

export default function VulnIndex() {
  return (
    <div className="vuln-grid">
      {CLASSES.map((c) => (
        <div className="vuln-card" key={c.code}>
          <span className="vuln-icon">{c.code}</span>
          <h3>{c.title}</h3>
          <p>{c.detail}</p>
          <span className="owasp">OWASP LLM Top 10 — {c.owasp}</span>
        </div>
      ))}
    </div>
  );
}
