# C08 MCP response-budget checkpoint (not stage acceptance)

This additive slice makes the already opt-in private MCP listener charge its
complete SDK response body before any bytes are returned. The same durable
query ledger now reserves at most 16 tool invocations per bound run and at
most 131072 MCP response-body bytes across initialization, list and calls.
Oversized or unchargeable responses fail closed with an empty refusal. A
legacy MCP binding without counters is refused on open rather than silently
resetting an unknown spent budget; an empty legacy table can be migrated.

Focused tests cover the actual Unix initialize/list/call bytes against ledger
usage, durable 16-call and 128-KiB boundaries across reopen, one-binding
replay refusal, and legacy-budget refusal/migration. The feature command
`cargo test -p tos-health-services --features mcp --test query_ledger --test mcp
--test mcp_token_visibility --bin tos-observability --locked -j2` passed:
3 binary, 1 SDK, 1 visibility, 6 ledger tests. Raw log:
`/home/tomi/nhm-c08-mcp-evidence/budget-feature-tests.log`, SHA-256
`189d9e2197ae1821d7d2620bc3e85097f98978e46eeffc2c33744c5d5882b24a`.
`cargo clippy --workspace --all-targets --features mcp --locked -j2 -- -D warnings`
passed; raw log `/home/tomi/nhm-c08-mcp-evidence/budget-clippy.log`, SHA-256
`92ef9322bf3f184ba439449532d8081988acea1436353681cda5d8669fda2e9b`.
`cargo fmt --all` and `git diff --check` passed.

These checks do not establish the remaining C08 gates: whole-run 180-second
termination, two-child concurrency, provider/AURA compatibility, actual
zero-upstream storm controls, or production deployment. `wire_bytes` denotes
HTTP response body bytes, not socket framing or headers. The MCP feature is
still disabled by default.

Successor boundary check: the private MCP connection is capped at 180 seconds
from accept, and the durable binding rejects calls or response release at
`bound_at_ms + 180000` even while the 200-second grant remains active. A
focused virtual-clock control passed at `+179999` and refused at `+180000`;
actual Unix and ledger tests and feature strict clippy passed after this edit.
The successor `cargo test -p tos-health-services --features mcp --test query_ledger
--bin tos-observability --locked -j2` raw log is
`/home/tomi/nhm-c08-mcp-evidence/session-deadline-tests.log` (SHA-256
`40de848a2e437aa931975a8cb8a518765c7f774121b8bc4cfc18cfae88f7cb84`);
strict feature clippy is `session-deadline-clippy.log` in that directory
(SHA-256 `dd621e9ff7c9eac161c730aa8a79332dd68698435a7a84d044d9ad39dfa1f5d2`).
This is a transport-session deadline, not yet proof of whole AURA child
termination or a complete broker-run deadline.

The later 32-KiB slice applies the per-response limit to the serialized SDK
body before release. The same bounded-body helper used by the Unix listener
accepts 32768 bytes and refuses 32769 without a partial body; the actual Unix
SDK initialize/list/call control remains green. This is a helper boundary
negative plus a real positive route, not an oversized SDK result fixture.
Focused feature tests exited 0: `/home/tomi/nhm-c08-mcp-evidence/response32-tests.log`
(SHA-256 `8d41abf3a94464b886341b9152b217aea50a806fb8b01a2aa08454a9296dc174`).
Strict feature clippy exited 0: `response32-clippy.log` in that directory
(SHA-256 `2cc52da353e70f4aedc4feb84c1ff98e5c6181b7b7bfcd263d88af8c530ea5aa`).
