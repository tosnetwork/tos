# C07/C08 pinned AURA integration plan — approval boundary

Status: implementation plan, **not** AURA end-to-end or production acceptance.
Source baseline `da8f89877807c985a8ffb18b4307c91912e7d580` is clean and
pushed. This plan precedes adapter implementation. It supersedes additional
unrelated cursor/evidence test expansion.

## Verified interfaces and exact dependencies

- Pinned AURA source: `1000f119d38f4c4656ced0ae883c90f6f7610890`
  (`/home/tomi/nhm-aura-source.dujJrk`). `McpServerConfig::Stdio` launches
  a child through `TokioChildProcess`; `McpManager::initialize_from_config`
  discovers tools and `execute_fallback_tool` calls them. Its URL-only
  `McpClient::new` cannot address a Unix socket. AURA's lock pins
  `rmcp 0.12.0`, checksum
  `528d42f8176e6e5e71ea69182b17d1d0a19a6b3b894b564678b74cd7cab13cfa`.
- NHM's optional MCP feature pins `rmcp 3.5.0`, checksum
  `fae7019994ae0fe4ada40b732f798f3ff26f0f04facb1477f1bf37eb4f18a2d3`.
  `tos-observability` serves Streamable HTTP/JSON over an already-private
  Unix socket, one durable grant per connection. It requires service
  Authorization plus run ID and 256-bit token on admission, then uses the
  existing six HTTP query handlers and one durable ledger. No TCP listener
  or second evidence path is proposed.
- Adapter dependencies: existing NHM `tokio`, `hyper`/`hyper-util`,
  `http-body-util`, `serde_json` and Unix sockets. Prefer a bounded
  line-delimited MCP stdio ⇄ HTTP/1-over-Unix process over adding a third MCP
  SDK/version to the NHM workspace. Protocol compatibility is an *actual
  test gate*, not inferred from matching method names.

## Minimal transport and authorization

1. One feature-gated `tos-nhm-aura-stdio` process is spawned by AURA's
   `McpServerConfig::Stdio`. It accepts only bounded UTF-8 JSON-RPC lines on
   stdin and emits only JSON-RPC lines on stdout. It forwards them to
   `/mcp` over **one** persistent Unix HTTP/1 connection, retaining MCP
   session headers as required. No shell, arbitrary URL, filesystem tool,
   alternate MCP server, or TCP fallback is allowed. The existing NHM
   listener remains the only service endpoint and owns all query budgets.
2. Broker creates a per-run private credential handoff (development profile:
   a 0600 regular file in a 0700 temporary directory, removed on connection
   success or failure). Only its pathname is present in AURA stdio config;
   never put the raw run token or service credential in `cmd`, `args`,
   AURA-config `env`, JSON-RPC/tool schema/result, or logs. The adapter checks
   file ownership/type/mode, reads it once, opens the fixed Unix path and
   presents the three authorization headers. The model is not given file,
   shell, network, or other MCP tools. A production handoff must additionally
   prove process-user/sandbox separation or replace this file with a one-use
   broker channel; the dev profile does not claim that gate.
3. `tools/list` must expose exactly the six existing NHM names/schemas.
   Every `tools/call` uses the frozen grant and QueryService; the adapter may
   not manufacture a response, retry a failed call, refresh source data, or
   forward a caller-supplied token. Bound each stdio line to 16 KiB input,
   each HTTP/MCP output to 32 KiB, whole run to the existing 16-call/
   128-KiB/180-second/200-second grant limits and five-second tool deadline.
   Adapter buffering and response framing need separate bounded accounting.
4. On cancellation, timeout, malformed frame, authentication failure or
   unexpected EOF, fail closed: stop forwarding, terminate/reap the AURA
   child and adapter, revoke the grant, and wait for termination before a
   replacement run. The broker's current `confirm_stopped` is only a state
   primitive; an actual supervised subprocess is required for this gate.

## Ordered local verification

1. Compile the adapter with the optional MCP feature. Wire-level tests use
   the actual private Unix server: initialization, tool discovery, six calls,
   typed envelope/schema checks, immutable W, grant charge, and no duplicate
   result representation. Exercise malformed, oversize, replay, second
   connection, denied scope and socket disconnect; verify no token appears
   in schema, stdout or retained logs.
2. Build pinned AURA from its exact lock in a separate target directory;
   use **its** `McpManager::initialize_from_config` with the adapter as a
   `Stdio` child, then call all six tools through AURA APIs. Record source,
   binary, config and raw log hashes. AURA 0.12 ⇄ NHM 3.5 protocol mismatch,
   if any, is a red to fix rather than an assumption. Run cancellation and
   child-reap controls on this path.
3. In an isolated local NHM fixture, feed a reproducible abnormal node
   snapshot and an explicit unknown/partial control. Have the AURA-side
   consumer read the delivered six-tool evidence and validate a structured
   English diagnosis against delivered IDs, unknowns and no severity/
   remediation authority. A deterministic local provider stub can verify
   orchestration/validation only and must be labelled **not a real model
   judgment**. A genuine local model run requires a separately selected,
   installed local model and measured context/cost; external API remains off.
4. Only with owner-approved C09 node access may the same path read live local
   node evidence. No business node is started, restarted or reconfigured by
   this work. Capture the actual source/epoch/grant provenance; do not
   substitute synthetic rows for production observations.

## Inputs/rulings still missing

- Owner-approved model/provider choice and private endpoint or a specific
  installed local model; no external model call is authorized now.
- Exact C09 local node/manager evidence endpoint and read-only credentials,
  if live-node abnormality rather than isolated fixture judgment is required.
  Supervisor owns C09 lifecycle; this worker will not start business nodes.
- Production credential-handoff/sandbox profile and confirmation that the
  development-only 0600 file profile may be used for the isolated AURA
  compatibility test. The latter is not a production permission claim.
