# C07/C08 reconciliation (development scope)

Baseline: `35ba59c111dd74518e6e661bcd1984598d493907` (C05 scoped acceptance). C06 belongs to Starbridge's isolated tree; C09 local-node lifecycle belongs to the supervisor. This document records gaps, not acceptance.

| Contract | Existing implementation | C07/C08 closure work |
| --- | --- | --- |
| Six cache-only tools | `health-core/query.rs` and typed `query_output.rs`; actual HTTP router tests | Preserve source/scope/window/W behavior; test MCP and HTTP parity and error semantics |
| 256-bit grant token | Random token and SHA-256 digest in `Grant`; 200-second in-process TTL | Durable grant/call/byte/delivered-ID ledger with conservative restart handling; broker-only control socket; service credential remains separate |
| Evidence and watermark | Baseline 8 MiB bounded in-memory `EvidenceStore`; read-only QueryService | Initial SQLite WAL/FULL write-through and exact store-sequence restoration now implemented for the optional query process; fixed-W HTTP restart control passes. Grant-pinned retention, stable pagination and production M integration remain open. |
| Per-run limits | 16 calls, 16 KiB input, 32 KiB response, 128 KiB returned bytes in HTTP service | Atomic durable accounting including MCP structured/text duplicate bytes, two child requests, 5-second tool deadline and 180-second run deadline |
| Pagination | Query code has cursor validation over in-memory W | Restart/cross-run/scope/token/expiry/late-record controls against durable W and stable sort key |
| MCP | Artifact/version inventory only (`rmcp` 3.5.0, protocol 2025-06-18); no endpoint | Actual pinned SDK integration, exactly six tools through existing QueryService, protocol/host/origin/session/error/cancel tests |
| C07 fixed package | `Broker` queue/cooldown skeleton; no package or model wiring | Immutable bounded package at M watermark, delivered-ID validation, English diagnosis schema and conservative evidence/basis checks |
| AURA/provider | Pinned commit `1000f119d38f4c4656ced0ae883c90f6f7610890`, disabled | Inspect exact source/config and isolate tools/egress; owner model/private endpoint choice pending, so no external API or actual provider-pass claim |
| Zero upstream | QueryService has no upstream client | Counter-based storm/miss/depth/redirect/replay controls with actual V/O request counters; no on-demand refresh |

Implementation sequence: (1) durable grant and evidence ledger with crash/restart negatives; (2) broker-only control and shared HTTP/MCP service with exact SDK/protocol; (3) fixed evidence package and offline broker validation/cancellation; (4) isolated AURA and provider tests only after explicit owner choice. Preserve historical scoped C00–C05 claims; neither this plan nor unit tests promote production capabilities.

Checkpoint note: `tos-observability` now requires a private ledger DB and Unix control socket. Its query process still uses an 8 MiB clone-on-insert candidate to commit SQLite before publishing a cache row; measure or replace this copy before any production cost claim. The old in-memory-only router remains solely for existing isolated tests. The checkpoint is not a C08 acceptance or evidence that Manager's main EvidenceDb query path is integrated.
