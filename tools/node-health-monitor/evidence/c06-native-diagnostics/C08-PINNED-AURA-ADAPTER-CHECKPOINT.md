# C08 pinned AURA adapter checkpoint — isolated development only

Source baseline: `0c48b1c847da720e29c27e07410b6d56aa40bd92`
(the transport plan commit). Pinned AURA source is
`1000f119d38f4c4656ced0ae883c90f6f7610890` in
`/home/tomi/nhm-aura-source.dujJrk`; NHM and AURA use their own locked Cargo
dependency sets and separate target directories. This is not C08 acceptance.

## Observed path

`McpManager::initialize_from_config` in actual pinned AURA launched
`tos-nhm-aura-stdio` through `McpServerConfig::Stdio`. The adapter made one
private Unix HTTP/1 connection to actual `tos-observability`, with the grant
token confined to the private credential file and HTTP headers. AURA
discovered exactly six NHM tools and called all six through
`execute_fallback_tool` against a **synthetic** retained process record.
Capabilities, node snapshot, event window, and change history returned `ok`;
metric window and block evidence returned `error` because their sources were
absent. The snapshot contained the fixture's RSS `8589934592` bytes. No model
was invoked and no business node was sampled or started.

The direct NHM test separately exercised 2025-06-18 initialize, all six
typed tool envelopes, exact tool list, rejection of a world-readable
credential file, no token in tool results/stdout, and second-connection
single-use-grant replay refusal. The pinned AURA run exercised its native
2025-03-26 initialize path. The protocol mismatch was observed red first,
then fixed by explicit two-version support; no other version is admitted.

## Exact source and binary hashes (SHA-256)

| Artifact | SHA-256 |
| --- | --- |
| `crates/health-services/Cargo.toml` | `e5da6f079b5f0d4a7f8d0142fdff9d8e9aa6e40db65247e35ecb6bfaace47124` |
| `crates/health-services/src/bin/tos-observability.rs` | `548e1fad19abb1a0b6a10753ecbba17093853f6e7bcde10bee842cc43a7187eb` |
| `crates/health-services/src/mcp_bridge.rs` | `b17c1291797fa1ac6b5c4af3aff751010fad08b22f954ad6c85be0b3e784ae87` |
| `crates/health-services/src/bin/tos-nhm-aura-stdio.rs` | `deb18bfba9bae1aa943c5e1540d4a5ac40cb49634735d88cf5ac78187b8a2333` |
| `crates/health-services/tests/aura_stdio.rs` | `18505dcc94a977bfd1a5cc224c2fa3e55792cc13a9d08b3f4b35a579938f874d` |
| `tests/pinned-aura/nhm_stdio.rs` | `dbb7b4cdba0252bc796880b1b115ea4708fd6898ad5fc80ee2d67c8ca2c06ccd` |
| `/home/tomi/nhm-c08-build/debug/tos-observability` | `babb171de3feb9c075276903224a730a79884794bced3ac3914f2fe33cb8389a` |
| `/home/tomi/nhm-c08-build/debug/tos-nhm-aura-stdio` | `c2a26d87c01261ca740de6b0be90d001c7458850f3cddfccec7ce85b841dcb1e` |
| `/home/tomi/nhm-aura-build/debug/deps/nhm_pinned_stdio-30dd84a3124e704c` | `be4992a2835045688df4991c2223ce248e2d349d9cbb899e8ce31e01619a3330` |

## Raw commands, results and lineage

Raw files are under `/home/tomi/nhm-c08-mcp-evidence/` and the hashes below
name their exact bytes. The pinned AURA test was included into its local
checkout's `crates/aura/tests/nhm_pinned_stdio.rs` from the NHM indexed test
source; the pinned AURA commit and lock were not changed. Its build required
`CXXFLAGS='-include cstdint'` because the vendored `sentencepiece-sys 0.11.3`
C++ compilation otherwise failed on a missing `<cstdint>` include. This is a
local build workaround, not a changed dependency or production fix.

| Raw log | SHA-256 | Result |
| --- | --- | --- |
| `aura-pinned-build-red.log` | `82ebd8c9137e0462e55efd6e3cd6af6a15b4139c1c4e2cbe2ddb80999a84ec64` | exit 101, original `sentencepiece-sys` compile red |
| `aura-pinned-six-tools-first.log` | `82b0b44ffe0281ce1b3145aea7764546519e39c1f8db9fb0fe337cb19c6a04bd` | red, AURA 2025-03-26 protocol refused by first adapter |
| `aura-pinned-six-tools-v2.log` | `adfd9ef898333839e49e728a4b1485e4cfe58cb505b6933f84b487b5300473ea` | red, overly strict harness asserted an envelope `tool` field absent from the actual contract |
| `aura-pinned-six-tools-final.log` | `9f5a8a21af80d82d0e5e09c6403e6b0e75ea171f5472e1cdd5127668d5a0419a` | exit 0, real AURA client six calls (4 ok/2 source-unavailable error) |
| `aura-adapter-workspace-final.log` | `a7144706c97611ec932daf1dfda89f94b0435729bc66796a3c9db97010831c03` | exit 0, `cargo test --locked --workspace --features mcp`, 226 passed across 39 results, one native-pair test ignored without its indexed C++ fixture |
| `aura-adapter-clippy.log` | `22c927047b0fb5e5fdcaeb7c99d53863bdd263fad8243f0137921400c60b08a0` | exit 101, new test's redundant async wrapper only |
| `aura-adapter-clippy-restored.log` | `b9be4ccb6414ecc00258ea65b24c7dbff5564f46f0f8fc32bf365bdb27d75264` | exit 0, `cargo clippy --locked --workspace --all-targets --features mcp -- -D warnings` |
| `aura-adapter-fmt.log` | `b538573e6bb8b782340625c693930b0734df7ac81b759e34e2ea632c07db2965` | exit 0, `cargo fmt --all -- --check` |
| `aura-adapter-targeted-final.log` | `7287bf7d4e0eb6be0f8427923edf48c44b8e2a6284001cee4f37453630c545b3` | exit 0, actual adapter test after clippy-only edit |

Pinned AURA command: `CXXFLAGS='-include cstdint' NHM_OBSERVABILITY_BIN=/home/tomi/nhm-c08-build/debug/tos-observability NHM_AURA_STDIO_BIN=/home/tomi/nhm-c08-build/debug/tos-nhm-aura-stdio CARGO_TARGET_DIR=/home/tomi/nhm-aura-build cargo test --locked -p aura --test nhm_pinned_stdio -- --nocapture` (bounded by 60 seconds externally, `-j2` for the initial build). NHM commands ran in `tools/node-health-monitor` with target `/home/tomi/nhm-c08-build`. `git diff --check` exited 0.

## Open boundary

The isolated development credential handoff is a 0600 file in a 0700
directory. The test owner deletes its temporary directory; a production
broker still needs a supervised child/process-user boundary, guaranteed
credential cleanup on all failures, termination/reaping and grant revocation.
No approved local model or provider endpoint, no C09 read-only live-node
source/credentials, and no authorized external model egress were available.
Thus this is genuine AURA **client** integration, not AURA model judgment,
real-node abnormality monitoring or deployment acceptance.
