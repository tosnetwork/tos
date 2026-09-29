# C08 MCP token isolation review

The first draft added `run_token` to every model-visible MCP tool input schema and read it from `tools/call` arguments. This violated R4's requirement that the grant token never enter a prompt or tool argument. Its original red result is retained as lineage.

The bounded regression `crates/health-services/tests/mcp_token_visibility.rs` compiled under `--features mcp` and failed at `run token exposed by "tos_get_capabilities"` (exit 101). Raw output: `/home/tomi/nhm-supervision/c06-c09-review/c08-mcp-token-visible-red.log`.

The subsequent connection-bound draft removes the token from tool schemas and rejects it in model arguments. The same regression now passes (exit 0), with raw output `/home/tomi/nhm-supervision/c06-c09-review/c08-mcp-token-visible-restored.log` and `mcp_bridge.rs` SHA-256 `d1b0294fdf5941bf4484aef7761dc1dd3e86360904400e9eb30ea0c04980a2f5`. This is a narrow token-visibility result, not an MCP acceptance result.

Remaining review: the private Unix listener must enforce its service and grant header checks on the real connection, durably claim the active grant once, reject a second connection and cross-session reuse, and pass all six calls through the existing durable query handler. Preserve the eight-connection bound and finite session lifetime. Do not expose the token in errors, logs, content, or prompts.

The current draft uses a private mode-0600 Unix socket, service Bearer and run headers at connection admission, a single durable `claim_mcp`, and a connection-owned bridge. The real-socket test must bind those claims to the exact source before acceptance. A model-supplied `run_token`, wrong peer, wrong run, second connection, and restart replay remain explicit negatives to verify. The five-second control-socket limit is separate from the MCP session lifetime.

Executor evidence correction: on direct inspection, the cited
`c08-mcp-token-visible-red.log` (SHA-256
`1fe43d23352952b0152578572572e45e17d26fa5f68d449acca1466678983f8c`)
contains only `error: could not find Cargo.toml` in the repository root. It
does **not** establish a compiled assertion failure, so the original red
claim above is withdrawn pending a separately indexed isolated mutation.
