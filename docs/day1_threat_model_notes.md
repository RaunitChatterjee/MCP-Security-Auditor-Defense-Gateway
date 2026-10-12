# Day 1 — MCP Threat Model & Vulnerable-Range Notes

## Why MCP, why now
MCP (Model Context Protocol) standardizes how LLM agents call external tools
and data sources. It's young infrastructure moving fast — SDKs across
Python, TypeScript, Java and Rust, a rapidly growing ecosystem of
community-built servers, and (per the 2026 disclosure wave referenced in the
project brief) a large number of CVEs surfaced across official SDKs in a
single quarter. Several of those flaws are architectural — missing-by-default
auth, implicit trust between "authorized" tool calls — not just sloppy
individual servers. That combination (young protocol + fast adoption + weak
default posture) is exactly the profile of early-2000s web-app security,
which is the framing this project uses.

> Note: this notes file deliberately does not cite specific CVE identifiers
> from memory — exact CVE numbers should be pulled from the NVD / GitHub
> Security Advisories at write-up time (Day 18) rather than recalled, to
> avoid citing a wrong or hallucinated ID in a public report.

## Vulnerability classes modeled in this range

| # | Class | Real-world shape | Range server |
|---|-------|-------------------|---------------|
| 1 | OS/"STDIO" command injection | Tool argument reaches a subprocess shell unsanitized | `server1_cmdinj` (git-helper-mcp) |
| 2 | Path traversal | File-access tool doesn't contain the resolved path to its sandbox | `server2_traversal` (project-files-mcp) |
| 3 | Missing/weak authentication | Tool invocation accepted without verifying caller identity | `server3_noauth` (Day 3) |
| 4 | Over-permissioned tools | A tool exposes more capability than its stated purpose needs | `server4_overpriv` (Day 3) |
| 5 | Sequence-level exfiltration | Individually "authorized" calls chained into an unauthorized outcome | attack script, Day 8 |

## Why JSON-RPC-over-HTTP instead of the official `mcp` SDK
The official `mcp` PyPI package's current release has a broken internal
import in this build environment (`mcp.shared.experimental.tasks` imports a
constant missing from `mcp.types`) and a pinned 1.x install wasn't honored by
the available package index. MCP's wire protocol is just JSON-RPC 2.0 with a
fixed method set (`initialize`, `tools/list`, `tools/call`), so the range
uses a small (~150-line) hand-rolled server runtime (`range/common/mcp_lite.py`)
that speaks the protocol directly over Streamable HTTP. This is a reasonable,
defensible choice for a vulnerability-research range specifically: it keeps
every byte of server behavior — including the injected vulnerabilities —
fully auditable, with no SDK internals to account for when explaining the
exploit chain in the write-up/demo.

## Exploit confirmation (Day 2 deliverable: "exploitable end-to-end")

**Server 1 — command injection**, via `git_log(author=...)`:
```
author = "' ; echo PWNED_CMDINJ ; id ; cat /etc/passwd | head -3 ; echo '"
```
→ returns `uid=0(root) gid=0(root) ...` and the first lines of `/etc/passwd`,
confirming arbitrary OS command execution with the server process's
privileges.

**Server 2 — path traversal**, via `read_file(path=...)`:
```
path = "../../../../../../etc/passwd"      # relative traversal
path = "/etc/hostname"                      # absolute-path bypass (os.path.join
                                             # discards the base dir for an
                                             # absolute 2nd argument)
```
→ both return file contents from outside the intended `workspace/` sandbox.

## IOC reference (partial — servers 1 & 2; 3 & 4 added Day 3-4)

| Server | Indicator | What a monitor should flag |
|---|---|---|
| git-helper-mcp | `author`/`pattern` argument containing `;`, `|`, `` ` ``, `$(`, `'` outside a plausible name/search string | shell metacharacters in a field typed as a human name/search term |
| git-helper-mcp | subprocess spawning a non-`git` child process (e.g. `cat`, `id`, `sh`) from the server's process tree | argument value never maps to a `git` subcommand or flag |
| project-files-mcp | `path` argument containing `../` segments, or resolving (after normalization) outside `workspace/` | resolved path escapes the declared sandbox root |
| project-files-mcp | `path` argument that is OS-absolute (`/etc/...`, `C:\...`) | absolute path passed to a tool documented as relative-only |
