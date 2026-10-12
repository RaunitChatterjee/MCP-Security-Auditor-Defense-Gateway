export default function Hero() {
  return (
    <section className="hero">
      <div className="wrap">
        <span className="eyebrow">4 vulnerable servers · live gateway · real attacks</span>
        <h1>Find and stop attacks against AI agent tools, automatically</h1>
        <p className="lede">
          AI agents call external tools through MCP (Model Context Protocol) —
          and most MCP servers today have little to no security. This project
          builds both sides: a scanner that finds the holes, and a gateway
          that blocks attacks in real time, in front of 4 intentionally
          vulnerable servers.
        </p>
        <div className="hero-actions">
          <a className="btn btn-primary" href="#live-attack">Watch it catch an attack live</a>
          <a className="btn btn-ghost" href="#findings">See the findings</a>
        </div>

        <div className="how-it-works">
          <div className="how-card">
            <span className="step-num">1</span>
            <h3>Scan</h3>
            <p>
              A static + dynamic scanner reads each server's declared config
              and actually probes it live, then scores every finding by
              severity.
            </p>
          </div>
          <div className="how-card">
            <span className="step-num">2</span>
            <h3>Defend</h3>
            <p>
              A gateway sits in front of every server. It blocks known attack
              patterns instantly, and watches whole call sequences for the
              sneakier stuff no single call reveals.
            </p>
          </div>
          <div className="how-card">
            <span className="step-num">3</span>
            <h3>Visualize</h3>
            <p>
              Everything below is real — real payloads, real servers, real
              gateway decisions. Pick an attack and fire it live, right from
              this page.
            </p>
          </div>
        </div>
      </div>
    </section>
  );
}
