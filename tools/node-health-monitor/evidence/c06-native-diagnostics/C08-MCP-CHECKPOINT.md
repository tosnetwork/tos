# C08 MCP development checkpoint — not acceptance

Base implementation commit: `474d9a3ee4843e28b6c16596a218a117a9ddfb88`.
The opt-in `mcp` Cargo feature pins registry `rmcp` exactly to `3.5.0` with
SHA-256 `fae7019994ae0fe4ada40b732f798f3ff26f0f04facb1477f1bf37eb4f18a2d3`
and protocol `2025-06-18`. The default feature remains disabled; no business
service was deployed or started.

The six SDK tools advertise the six original closed input schemas, without a
grant token. A private Unix HTTP connection authenticates the service and the
grant in headers, claims the run once in SQLite WAL/FULL, and owns the opaque
token only in server memory. The same connection can initialize, list and call;
a second connection or a reopen cannot claim that run again. Each call invokes
the existing HTTP QueryService and returns one JSON text representation, so
there is no second uncharged structured copy. Bad token, Host, Origin and
model-supplied token paths are refused in scoped tests.

Exact restored source hashes: `mcp_bridge.rs`
`d1b0294fdf5941bf4484aef7761dc1dd3e86360904400e9eb30ea0c04980a2f5`,
`tos-observability.rs` `452d8ad5ef54596581c422566bf4ad006ba9b492f388cf7f06c80038d3d6e760`,
`query_ledger.rs` `d0dc31d80a849b13991e268df00ba91f5dc72063357a198f776bd84837983fe5`,
`mcp.rs` `cd78d91d61cefb96bf97137ab556c0a855ad04f69e5c0e7522991d734057a27c`,
and supervisor's `mcp_token_visibility.rs`
`248a13666c778687025ca5a4b5429e42eb0e48eb0a5c91d5cba357f0086a0869`.

Raw local results: feature-gated binary/SDK/token tests 5 passed, exit 0,
`$HOME/nhm-c08-mcp-evidence/feature-tests.log` SHA-256
`5d3264e25bee8079af2a33c1725aedd9c20438ad6cac194d5ea23da73b4854fe`;
strict all-target feature clippy exit 0,
`$HOME/nhm-c08-mcp-evidence/strict-clippy.log` SHA-256
`8a2933ae25e59188be988ea6218274cb341f13d8bc4b533f57b12ececd4be8b3`;
24-schema checker exit 0, `$HOME/nhm-c08-mcp-evidence/contracts.log`
SHA-256 `04e7b638014f9b729ca7e243958c21bd2d2a3691ad9029217881e9dff3e53de0`.
Default-feature `cargo test --workspace --locked -j2` also exited 0 in the
terminal (including the three real C06 chain tests), but its full stdout was
not retained as a hashed raw file and is not represented as one here.
Format and diff checks exited 0. The [token-visibility mutation receipt](C08-MCP-TOKEN-MUTATION.json)
binds a clean disposable worktree at the base commit to baseline exit 0,
compiled intended assertion exit 101, and restored exit 0. The earlier
supervisor-named red log was a wrong-directory Cargo error and is excluded.

Open C08 gates: this strict single-connection transport profile still needs
actual AURA client compatibility, disconnect/cancel and child termination,
180-second run vs 200-second grant behavior, two-child and 16-call admission,
and complete 128 KiB accounting for every MCP-visible representation and
protocol result. Zero-upstream storm/redirect tests and provider selection are
not complete. Disconnect deliberately fails closed; reconnect needs a new
grant. None of these local results certifies production readiness.
