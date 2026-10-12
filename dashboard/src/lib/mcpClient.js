// Browser-side MCP client (Day 17) — mirrors client/harness.py's MCPClient,
// but calls the live gateway directly from the page via fetch, so "fire an
// attack from the dashboard" is a real JSON-RPC call over the network, not
// a simulation and not a server-side script invocation.

export async function callTool(gatewayUrl, serverId, sessionId, tool, args) {
  const resp = await fetch(`${gatewayUrl}/gateway/${serverId}/mcp`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Session-Id": sessionId },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: Date.now(),
      method: "tools/call",
      params: { name: tool, arguments: args },
    }),
  });

  let body = null;
  try {
    body = await resp.json();
  } catch {
    // non-JSON response — fall through, handled below
  }

  if (resp.status === 403 || body?.error) {
    const msg = body?.error?.message || `HTTP ${resp.status}`;
    const ruleMatch = msg.match(/\(([^)]+)\)/);
    return {
      verdict: "blocked",
      ruleId: ruleMatch ? ruleMatch[1] : "POLICY",
      message: msg,
      raw: "",
    };
  }

  const text = (body?.result?.content || []).map((c) => c.text || "").join("\n");
  const alertRule = resp.headers.get("x-gateway-alert");
  const alertTitle = resp.headers.get("x-gateway-alert-title");

  if (alertRule) {
    return { verdict: "flagged", ruleId: alertRule, message: alertTitle || "", raw: text };
  }
  return { verdict: "cleared", ruleId: null, message: text.slice(0, 140), raw: text };
}
