# Day 4 — IOC Reference Sheet (all 4 range servers)

Every payload below was run against the live range via `client/harness.py`
and confirmed to work (see Day 2 / Day 3 notes for the raw output). This
sheet is the reference the Phase 3 scanner's dynamic tester fires from, and
the reference Phase 4's gateway detection rules are built against — so each
entry gives the exact payload, the exact tool-call shape it travels in, and
the signal a monitor should flag.

---

## Server 1 — `git-helper-mcp` (OS/"STDIO" command injection) — port 8001

**Tool:** `git_log(author)`, `git_grep(pattern)`

**Confirmed exploit payload:**
```
author = "' ; echo PWNED_CMDINJ ; id ; cat /etc/passwd | head -3 ; echo '"
```
Call shape (JSON-RPC `tools/call` params):
```json
{"name": "git_log", "arguments": {"author": "' ; id ; cat /etc/passwd #"}}
```

**Expected IOCs:**

| Signal | Detection logic |
|---|---|
| Shell metacharacters in a name/search field | `author`/`pattern` argument matches `[;|&$\`'"]` or contains `$(` / backticks — these have no legitimate place in a human author name or grep term |
| Anomalous child process | server process (`python3`/`uvicorn`) spawns a child that is not `git` — e.g. `sh -c`, `id`, `cat`, `whoami`, `curl`, `wget` |
| Argument content doesn't match a `git` flag/value shape | `author` value contains a full shell pipeline (`|`, `;` chains) rather than a plausible `--author=` filter string |
| Output anomaly | tool response contains `uid=`/`gid=` (passwd/id output) or `root:x:0:0` (passwd file content) where a commit-log response was expected |

**Severity:** Critical — arbitrary command execution with server-process privileges.

---

## Server 2 — `project-files-mcp` (path traversal) — port 8002

**Tool:** `read_file(path)`

**Confirmed exploit payloads:**
```
path = "../../../../../../etc/passwd"   # relative traversal out of sandbox
path = "/etc/hostname"                  # absolute-path bypass
```
Call shape:
```json
{"name": "read_file", "arguments": {"path": "../../../../etc/passwd"}}
```

**Expected IOCs:**

| Signal | Detection logic |
|---|---|
| Traversal sequence in path arg | `path` contains `../` or `..\\` segments |
| Absolute path in a relative-only param | `path` starts with `/` (POSIX) or a drive letter / `\\` (Windows) when the tool is documented as sandbox-relative |
| Resolved-path escape | after `os.path.realpath()`, the resolved path does not start with the sandbox root — this is the authoritative check, independent of which bypass string was used |
| Sensitive filename accessed | `path` resolves to known-sensitive files: `/etc/passwd`, `/etc/shadow`, `.env`, `id_rsa`, `.git/config`, cloud credential paths (`.aws/credentials`) |

**Severity:** High — arbitrary file read with server-process privileges (confidentiality impact; becomes critical if credential files are reachable).

---

## Server 3 — `ops-console-mcp` (missing/weak authentication) — port 8003

**Tools:** `get_user(user_id)`, `update_balance(user_id, new_balance)`, `list_users()`

**Confirmed exploit payloads:**
```
# no auth header sent at all, for any of these:
list_users()                                    # full directory dump, incl. admin account
update_balance(user_id="u1003", new_balance="999999")   # unauthenticated WRITE on an admin account
```
Call shape (note: no `Authorization` header present):
```json
{"name": "update_balance", "arguments": {"user_id": "u1003", "new_balance": "999999"}}
```

**Expected IOCs:**

| Signal | Detection logic |
|---|---|
| Missing/absent auth header | `tools/call` (or any method past `initialize`) arrives with no `Authorization` header, or a header that doesn't match the expected scheme |
| Write-class tool called cold | a mutating tool name (`update_*`, `delete_*`, `create_*`, `set_*`) is invoked as literally the first request in a session — no prior read/lookup — a common signature of a scripted/automated probe rather than an agent working through a task |
| Privileged-record access by an anonymous caller | `user_id` argument targets a known privileged/service account (role=`admin`) with no session context establishing why |
| Full-enumeration call pattern | `list_users()` / any "list all" tool called with no filter argument — a legitimate agent task is almost always scoped to one record |

**Severity:** Critical — unauthenticated read AND write access, including to privileged accounts.

---

## Server 4 — `crm-assistant-mcp` (over-permissioned tool scope) — port 8004

**Tool:** `lookup_customer(customer_id, filter)`

**Confirmed exploit payload:**
```
lookup_customer(customer_id="nonexistent", filter="1=1")
```
Call shape:
```json
{"name": "lookup_customer", "arguments": {"customer_id": "nonexistent", "filter": "1=1"}}
```
Returned all 3 rows in the table — the tool's documented scope is "one
customer, by ID."

**Expected IOCs:**

| Signal | Detection logic |
|---|---|
| Optional/undocumented parameter populated | `filter` is not part of the tool's advertised single-ID-lookup purpose — any non-empty `filter` value is itself a scope-violation signal, independent of its content |
| SQL-shaped content in a non-SQL-typed field | `filter` value contains SQL keywords/operators (`OR`, `=`, `--`, `UNION`, `;`) |
| Row-count mismatch vs. intended scope | tool documented/expected to return ≤1 row returns >1 row |
| Response contains records unrelated to the requested ID | returned `customer_id` values differ from the `customer_id` argument supplied |

**Severity:** High — unscoped data exposure across the full backing table; escalates to Critical if the free-form field is also inJECTABLE into a privileged query (it is, here — classic compounding of a scoping bug with an injection bug).

---

## Cross-server patterns (useful for the Phase 3 scanner's severity model)

- **Servers 1, 2, 3 all share "no authentication at all"** at the transport
  level — only server 3 is *classified* as the auth-missing example because
  its tool logic is otherwise correct; 1 and 2 are classified by their
  distinct injection/traversal bugs instead. A real scanner finding against
  this range should flag missing auth on *all three*, in addition to each
  one's specific class-level bug — this is intentional and worth calling
  out explicitly in the scanner's README as "classes aren't mutually
  exclusive; a server can and does fail more than one check."
- **Argument-shape mismatch is the single most reusable static signal**
  across all 4: in every case, the exploit payload doesn't look like the
  kind of value the tool's own schema/description implies (a name field
  getting shell syntax, a relative-path field getting `../`, a single-ID
  field getting a boolean SQL expression). The Phase 3 static scanner can
  implement one general-purpose check — "does the argument value's
  character class match what the tool's description promises?" — and catch
  variants of all four classes, not just these exact payloads.
