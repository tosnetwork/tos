# C08 pinned AURA adapter checkpoint — isolated development only

Source baseline: `0c48b1c847da720e29c27e07410b6d56aa40bd92`
(the transport plan commit); preceding adapter checkpoint is
`0710a9a4f2e616b2be407f23d51af3842c69db33`. Pinned AURA source is
`1000f119d38f4c4656ced0ae883c90f6f7610890` in
`/home/tomi/nhm-aura-source.dujJrk`; NHM and AURA use their own locked Cargo
dependency sets and separate target directories. This is not C08 acceptance.

## Observed path

`McpManager::initialize_from_config` in actual pinned AURA launched
`tos-nhm-aura-stdio` through `McpServerConfig::Stdio`. The adapter made one
private Unix HTTP/1 connection to actual `tos-observability`, with the grant
token confined to the private credential file and HTTP headers. AURA
discovered exactly six NHM tools and called all six through
`execute_fallback_tool` against **synthetic** retained process and warning
records.
Capabilities, node snapshot, event window, and change history returned `ok`;
metric window and block evidence returned `error` because their sources were
absent. The snapshot contained the fixture's RSS `8589934592` bytes. A bounded
local deterministic control accepted the actually delivered collector warning
only when its evidence ID appeared in the same AURA-returned envelope; it
returned `insufficient_evidence` for an unavailable warning control and kept
block/proof conclusions missing. This is a synthetic contract test, not a
production memory-pressure threshold, live-node diagnosis or model output.
No model was invoked and no business node was sampled or started by this test.

The direct NHM test separately exercised 2025-06-18 initialize, all six
typed tool envelopes, exact tool list, rejection of a world-readable
credential file, no token in tool results/stdout, and second-connection
single-use-grant replay refusal. The pinned AURA run exercised its native
2025-03-26 initialize path. The protocol mismatch was observed red first,
then fixed by explicit two-version support; no other version is admitted.
Source inspection confirms rmcp 0.12.0's `JsonRpcMessageCodec` frames stdio
with newline-delimited JSON, and the actual AURA calls crossed the adapter's
one persistent Unix HTTP/1 connection after initialize. NHM rmcp 3.5 sets
`legacy_session_mode=false`, so this tested POST path is stateless and issues
no `mcp-session-id`: an attempted mandatory-header check failed the direct
test and was removed. The adapter validates and forwards a session header if
one is supplied, but neither fabricates nor requires one. Pinned AURA
owns the `RunningService`/`TokioChildProcess`; rmcp's child drop schedules an
asynchronous kill/wait. A Linux `/proc` witness found exactly one adapter
child while AURA's manager lived and observed its PID disappear after manager
drop. This is normal-drop evidence only, not broker cancel/revoke/replacement
sequencing.

## Exact final source and binary hashes (SHA-256)

| Artifact | SHA-256 |
| --- | --- |
| `crates/health-services/Cargo.toml` | `e5da6f079b5f0d4a7f8d0142fdff9d8e9aa6e40db65247e35ecb6bfaace47124` |
| `crates/health-services/src/bin/tos-observability.rs` | `548e1fad19abb1a0b6a10753ecbba17093853f6e7bcde10bee842cc43a7187eb` |
| `crates/health-services/src/mcp_bridge.rs` | `b17c1291797fa1ac6b5c4af3aff751010fad08b22f954ad6c85be0b3e784ae87` |
| `crates/health-services/src/bin/tos-nhm-aura-stdio.rs` | `51a57791140a6782217dbf8887f324cd399a9a165ffbe2e123b48add95345558` |
| `crates/health-services/tests/aura_stdio.rs` | `4ff5589e4c6f0afea79283ac5748e1774a7f98d38061c530b438b4abfd95a0ce` |
| `tests/pinned-aura/nhm_stdio.rs` | `083c3fbd9c4e019922d75e968edae72fc6961cb6cb617cdb5583aecfc76cd6bb` |
| `/home/tomi/nhm-c08-build/debug/tos-observability` | `babb171de3feb9c075276903224a730a79884794bced3ac3914f2fe33cb8389a` |
| `/home/tomi/nhm-c08-build/debug/tos-nhm-aura-stdio` | `3eec9bb861eef89afc66503b0fc76e68717327e2187fb01d2fa7496a0f046396` |
| `/home/tomi/nhm-aura-build/debug/deps/nhm_pinned_stdio-30dd84a3124e704c` | `9a6582bf17e2fa5dec5defe87a785dad3f4a432746a64a5ad9110b3d14a5ffa0` |

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
| `aura-pinned-deterministic-first.log` | `7220ef7cb0d49114e76d7213f17cc33289bec75b29a8979fcab98e229a3ebfae` | exit 0, successor six calls plus synthetic warning/unknown control and observed normal child reap |
| `aura-pinned-deterministic-clippy.log` | `f798c26edd91993fd1ae43ad7521815e36a3b3ae761a662e3b889071a36cc5fe` | exit 0, pinned AURA test `cargo clippy --locked -p aura --test nhm_pinned_stdio -- -D warnings` |
| `aura-session-targeted.log` | `52b4cc76d96ee1ba5f79764321049d2661467bcf8a3aaa307c15d169977ac3ac` | exit 101, experimental mandatory session-header assertion contradicted actual stateless NHM configuration; reverted |
| `aura-session-restored.log` | `b6f4c7ddf20d07d8b117a0102e44d1c5367bc4d8890f5efdfbb56ad62aa8ffa7` | exit 0, actual direct private-Unix six-tool test with optional validated session-header handling |
| `aura-pinned-deterministic-restored.log` | `609f75d58139dce2f19389afab99fe8f26e8a491af15f47165668e804fa92603` | exit 0, final pinned AURA six calls, synthetic warning/unknown control and child-reap witness |
| `aura-session-clippy-final.log` | `76a02c09e10ccbd0c55cbc5c485c2cfe5e3ccab0eae98745087650decc029351` | exit 0, final NHM strict workspace clippy after stateless-session correction |
| `aura-session-fmt-final.log` | `7691ab977c5d6176ed084dcf8bd71e02530b66c555a3e26b19116b65c4c67e1a` | exit 0, final NHM workspace format check |
| `aura-pinned-final-handoff.log` | `0705d58a7d656e04cdbd4749448ec907367ffcf15d81c72ad531e0d05c0c4c81` | exit 0, preceding pinned AURA six calls and consumed-file assertion |
| `aura-handoff-workspace-final.log` | `42c02771612034658971115cb3461b79e5f03af42f5943918c512ed75b5d9bea` | exit 0, preceding `--features mcp` workspace 228 passed/one conditional native-pair ignored |
| `aura-handoff-clippy-final.log` | `53e91262a320beb21581f77a06d45e7305783694330c4c2a043b5a2c4cec5212` | exit 0, preceding strict NHM workspace clippy |
| `aura-handoff-fmt-final.log` | `85a3ca804da5d1982480d87ec5143c4c99e2437b716c8459e1e7258743c768ee` | exit 0, preceding NHM workspace fmt check |
| `aura-handoff-targeted-successor.log` | `67a78a19d9a29f0bda5a209100311aef2eee50ebfa52df6d81a42ded307a6722` | exit 0, preceding direct Unix 3-test suite before the explicit slow-body Drop assertion |
| `aura-pinned-handoff-successor.log` | `6d5e4bf4d18b929e9c5753b84e45569340ac777dc094f0058ce0ff98190e9bc4` | exit 0, final pinned AURA six calls and consumed-file assertion; tested AURA and NHM executable sources unchanged in the final test-only edit |
| `aura-handoff-workspace-successor.log` | `274d03f8c21eecd1e8325741903c78304a01bfe0093b4869ccb3aea55cbfb9da` | exit 0, preceding workspace 228 passed/one conditional native-pair ignored |
| `aura-handoff-clippy-successor.log` | `ef9815a2f64818164bb560f0577645f0c9d9d399bcf64350732fd0c285adcfe8` | exit 0, preceding strict NHM workspace clippy |
| `aura-handoff-fmt-successor.log` | `c8915c8954f9c82c90861651fd2cb7d68ba93702cd1a896c0ab6c20dffe2b2c7` | exit 0, preceding NHM workspace fmt check |
| `aura-handoff-targeted-final2.log` | `e661e909b71327ef3daeb386f4016e273612feaa9710197358a1c20753c19e60` | exit 0, final direct Unix 3-test suite including slow-body task Drop witness |
| `aura-handoff-workspace-final2.log` | `dc8c3bc33f3d355656b2f7beae9699d099ccabeae9b1d995287e8cf80a4bc632` | exit 0, final workspace 228 passed/one conditional native-pair ignored |
| `aura-handoff-clippy-final2.log` | `f9789979982dacabff635f0fc86f1f6042316598ce18376a99ab0a3294109865` | exit 0, final strict NHM workspace clippy |
| `aura-handoff-fmt-final2.log` | `ff81bfd5da0628a8f6da790825c4e85ab584c859d1cdff2a5e308c7c960e3fd0` | exit 0, final NHM workspace fmt check |
| `aura-adapter-workspace-final.log` | `a7144706c97611ec932daf1dfda89f94b0435729bc66796a3c9db97010831c03` | exit 0, `cargo test --locked --workspace --features mcp`, 226 passed across 39 results, one native-pair test ignored without its indexed C++ fixture |
| `aura-adapter-clippy.log` | `22c927047b0fb5e5fdcaeb7c99d53863bdd263fad8243f0137921400c60b08a0` | exit 101, new test's redundant async wrapper only |
| `aura-adapter-clippy-restored.log` | `b9be4ccb6414ecc00258ea65b24c7dbff5564f46f0f8fc32bf365bdb27d75264` | exit 0, `cargo clippy --locked --workspace --all-targets --features mcp -- -D warnings` |
| `aura-adapter-fmt.log` | `b538573e6bb8b782340625c693930b0734df7ac81b759e34e2ea632c07db2965` | exit 0, `cargo fmt --all -- --check` |
| `aura-adapter-targeted-final.log` | `7287bf7d4e0eb6be0f8427923edf48c44b8e2a6284001cee4f37453630c545b3` | exit 0, actual adapter test after clippy-only edit |

Pinned AURA command: `CXXFLAGS='-include cstdint' NHM_OBSERVABILITY_BIN=/home/tomi/nhm-c08-build/debug/tos-observability NHM_AURA_STDIO_BIN=/home/tomi/nhm-c08-build/debug/tos-nhm-aura-stdio CARGO_TARGET_DIR=/home/tomi/nhm-aura-build cargo test --locked -p aura --test nhm_pinned_stdio -- --nocapture` (bounded by 60 seconds externally, `-j2` for the initial build). NHM commands ran in `tools/node-health-monitor` with target `/home/tomi/nhm-c08-build`. `git diff --check` exited 0.

## Open boundary

The isolated development credential handoff is a 0600 file in a 0700
directory. The adapter now opens that directory without following a symlink,
checks file inode/owner/mode and one-link identity, unlinks the named entry
before reading or connecting, and refuses a second use. Tests prove absence
after success, bad file mode, missing socket, replay, symlink and hardlink
refusals; symlink/hardlink targets remain intact. A verified private parent is
required before any deletion, so an invalid/untrusted parent is refused
without attempting arbitrary cleanup. The adapter uses one 5-second deadline
for send, complete JSON body and stdout flush, serializes calls, and aborts
then awaits its HTTP connection task before exit. Mock slow-body and SSE
responses cannot forward a queued next call or emit partial stdout. rmcp 3.5
requires `Accept` to name both JSON and SSE even with `json_response=true`;
the adapter advertises both but explicitly rejects a non-JSON result. The
actual pinned AURA initialize/list/six calls pass under this exact rule.

A production broker still needs a supervised child/process-user boundary,
credential cleanup for its own failure before launch, guaranteed model-child
termination/reaping and grant revocation. The adapter's connection-task wait
does not prove remote handler work has ended or broker replacement sequencing.
The owner has authorized read-only local-node evidence and this development
credential profile, so neither is a waiting-for-approval gate. The isolated
test still used synthetic records; no C09 live-source projection or model
execution was part of this successor. A specific local model/private provider
profile has not been configured and external model egress remains disabled.
This is genuine AURA **client** integration and a deterministic local control,
not AURA model judgment, real-node abnormality monitoring or deployment
acceptance.

Read-only inspection of the running C09 development manager's evidence DB on
2026-09-29 found archived `edge_probe` reachability rows, but no `process`
rows. The current query projection is explicitly process-only and therefore
must not silently recast those live reachability rows as process, consensus,
or block evidence. This is an implementation/source-availability gap, **not**
an authorization gap; it does not invalidate the isolated AURA compatibility
or synthetic deterministic controls above.
