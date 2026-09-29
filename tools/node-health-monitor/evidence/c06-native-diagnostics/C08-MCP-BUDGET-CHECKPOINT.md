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
