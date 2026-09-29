# C08 MCP child bound and pinned AURA transport checkpoint

Feature-gated `McpBridge` service clones now share two owned permits per
admitted run. Each actual tool invocation reserves its durable attempt before
trying a permit; a busy invocation returns an empty error and never enters the
HTTP query handler. The permit spans route dispatch and the complete bounded
response body. One five-second deadline covers both phases, so a body that
never finishes cannot keep an invocation alive beyond the tool deadline.
This bounds service-side tool requests, **not** an eventual AURA model process
or its own child-task lifecycle.

An isolated actual bridge test holds both permits, calls the real tool path,
observes `isError=true`, query-grant calls=0 and durable MCP attempts=1;
after releasing one permit the same tool succeeds and counts the second MCP
attempt plus one query call. A body test uses a never-finishing HTTP body to
prove deadline refusal and checks the 32,768/32,769-byte boundary. The compiled
single-property mutant `Semaphore::new(2)→(3)` builds, then fails at the
third-call `isError` assertion (not a compile error); the original source is
restored and retested.

Pinned AURA source inspected at Git
`1000f119d38f4c4656ced0ae883c90f6f7610890`. Its
`crates/aura-config/src/config.rs` `McpServerConfig` permits stdio,
`http_streamable` and SSE but no Unix socket transport; SHA-256
`25bd572609612c506a331f9276706acbe7b6d3c22241b36c1ac7fd5264480d8f`.
Its `crates/aura/src/mcp/client.rs` `McpClient::new` builds a `reqwest`
client from a server URL; SHA-256
`d5fd65879f000e0455df92377bccfb327a8c70ca14225adb47e1bef2b68d2542`.
NHM currently exposes only private Unix HTTP. Therefore the pinned AURA
declarative client cannot directly attach to the existing endpoint. A bounded
transport adapter or separately approved alternative must be decided and
tested before calling this AURA integration complete. No TCP listener or
production provider was enabled here.

Source SHA-256 after restoration: `mcp_bridge.rs`
`1b8bad27038b0ec9553fc2b17cb8990694f5f91caa3e42e71f0881824bb41ab5`.
Reconstructed one-line mutant source SHA-256:
`ca046c69e5157873e9e7d52bf009bfd7889392d34bee0ac99abdf8c5fcd4af60`.

Raw logs under `/home/tomi/nhm-c08-mcp-evidence/`:

- `c08-child-bound-baseline.log`: exit 0, two targeted tests pass; SHA-256
  `196994e0b812eac921d2c46c759d956cc1192a17341484b81ee0a3fe83ddb5d4`.
- `c08-child-bound-mutant.log`: compiled test exit 101 at the intended
  third-call assertion; SHA-256
  `66afcf91e79777c9afa36b406de399a89ca996250d80d446e0cfd2851603cdbe`.
- `c08-child-bound-final-tests.log`: `cargo test --locked -p
  tos-health-services --features mcp --lib --test mcp --test
  mcp_token_visibility --bin tos-observability`, natural exit 0, 26 tests
  passed (20+4+1+1); SHA-256
  `af1ae18bd685ebe1c8078299d026cc99a9bef4986e922b692eb6be2024bee980`.
- `c08-child-bound-final-clippy.log`: `cargo clippy --locked --workspace
  --all-targets --features mcp -- -D warnings`, natural exit 0; SHA-256
  `5a3b2f02083d9ac89617ff520d3c8447d6104f8259262667d67ac32dc50a7f7e`.
  `cargo fmt --all -- --check` also exits 0.

No C07/C08 acceptance is claimed. Actual AURA child termination and replacement
gating, private provider selection, tokenizer/context costs, and zero-upstream
storm counters are still open.
