// The same payloads as scripts/exploit1-4 (Phase 2), fired live from the
// browser at the running gateway. "sequence" is handled specially by
// LiveAttackConsole: step 2+ are generated from step 1's real response,
// not hardcoded, same as exploit4_sequence.py does server-side.

export const LIVE_ATTACKS = {
  cmdinj: {
    label: "Command injection",
    description: "git_log(author=...) with a shell-metacharacter payload — server1, port 8001.",
    steps: [
      {
        serverId: 1,
        tool: "git_log",
        args: { author: "' ; id ; cat /etc/passwd | head -3 ; echo '" },
      },
    ],
  },
  traversal: {
    label: "Path traversal",
    description: "read_file(path=...) escaping its sandbox — server2, port 8002.",
    steps: [
      {
        // 12 "../" safely overshoots filesystem root regardless of how
        // deep the project happens to be installed on a given machine —
        // excess ".." segments are a no-op once you hit "/" on POSIX.
        serverId: 2,
        tool: "read_file",
        args: { path: "../".repeat(12) + "etc/passwd" },
      },
    ],
  },
  noauth: {
    label: "Unauthenticated access",
    description: "list_users() with no Authorization header — server3, port 8003. The gateway doesn't enforce auth itself (that's the scanner's job) — this run is expected to come back CLEARED, which is itself the point: it shows exactly where the gateway's coverage ends.",
    steps: [
      { serverId: 3, tool: "list_users", args: {} },
    ],
  },
  sequence: {
    label: "Sequence-level exfiltration",
    description: "Read an ID list (server2), then loop single-ID lookups over it (server4) — each call individually legitimate.",
    isSequence: true,
    firstStep: { serverId: 2, tool: "read_file", args: { path: "customer_ids.txt" } },
    harvestStep: (id) => ({ serverId: 4, tool: "lookup_customer", args: { customer_id: id } }),
  },
};
