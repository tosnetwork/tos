# Explorer PQ RPC implementation

R1–R4 from the [reviewed design](explorer-pq-rpc-design.md) are implemented in
the native JSON-RPC server. The original design source pin is historical;
implementation starts at merge base `018fc46b2`. Local validation is described
below. Linux analysis and pull-request CI are separate acceptance gates and are
not implied by local results.

## Interfaces and compatibility

| Boundary | Implemented behavior | Regression evidence |
| --- | --- | --- |
| R1 `getMasterchainBlockSignatures` | Full-ID or height selection, native anchored PQ finality verification, exact native signing payload and signer IDs, optional raw proof | Native forward-proof suite; frozen ordinary-predecessor proof; three-node response agreement |
| R2 `getAccountCapability`, `getWalletInformation` | `include_pq: true` adds authenticated public authorization metadata for six exact compiled code identities | All six public genesis fixtures; malformed recognized code; unknown code; inactive account; unsigned 64-bit extrema |
| R3 `getProofQuery` | Named REST and JSON-RPC share the existing read-only TL allowlist, authentication and budgets | Exact pinned Config8 reply parity; forbidden send/nested queries fail before backend access |
| R4 `getConfigParam` | `include_decoded: true` adds native Config8/43/47/48 projection and explicit authenticated absence | Native wire-version/default/retirement tests; VM18 and VM16 networks |

R2/R4 default calls retain their legacy builders and missing-config behavior.
Classical signature rendering retains its existing result shape. Typed calls
bypass the legacy height-oriented response cache. A selected block is resolved
once; replies and optional proofs must match the complete immutable ID.

R1 obtains the target and predecessor from locally validated masterchain history.
The existing native proof validator authenticates every backward and forward
link, derives the historical validator session, checks finality signatures and
reports checked weight. A session carried in the reply cannot become its own
trust anchor. A genesis block is unsigned, and unavailable historical state is
reported rather than replaced with current state.

R2 checks exact compiled code hashes before decoding storage. The build registry
is generated from native contract sources and records compiler/source hashes;
there is no runtime plugin or arbitrary-file ABI lookup. The default Quantum
wallet registry is the public candidate network tag `42` repeated 32 times.
Operators targeting another compiled wallet namespace must set
`TOS_EXPLORER_QUANTUM_NETWORK_TAG` at CMake configuration time and distribute that
build's registry manifest. Public state is observational: it does not attest
private-key possession, successful signing, admission or release readiness.

## Access and availability limits

Existing API-key header validation, route dispatch, ingress rate limits, body
budgets and batch admission apply to the new paths. No new write, signing or
unrestricted native-query endpoint is added.

| Resource | Bound |
| --- | --- |
| Expensive native inspections | Process-wide default 2; `TOS_EXPLORER_RPC_JOBS` permits 1–8; invalid values use 2 |
| Waiting inspection queue | 0; exhaustion returns existing HTTP 429 response |
| Inspection deadline | At most 30 seconds, including configurations with a disabled legacy request timeout |
| R1 proof / links / JSON | 8 MiB / 64 / 16 MiB |
| R2/R4 proof / JSON | 4 MiB / 8 MiB |
| Account code and data inspection | 2,048 distinct ordinary level-zero cells; depth 128; combined serialized size 256 KiB |
| Raw proof relay request / reply | Existing 16 KiB request and 64 MiB reply caps; at most 64 configuration IDs or 16 library hashes |
| Pending explorer output | 192 MiB process-wide, reserved before backend work; includes slow writers and drained batch elements |

Proof parsing and cryptographic verification execute on bounded workers. Timeout
cancellation does not release a running worker's permit early. Output reservations
remain owned through the HTTP payload lifetime and are reduced to actual output
size after rendering. Raw proof output is opt-in on typed views.

## Local validation and reproducibility

Host: macOS arm64; Release AppleClang 21 build with RocksDB and QUIC enabled.
These results do not substitute for Linux, ASan, production or deployment tests.

The final local native selection contains 14 CTest entries: explorer, parser,
legacy account capability, native forward proofs, getter fixture/budget/query
service/boundary/admission/completion, proof relay, and three PQ carrier/vector
suites. Direct transport tests cover selector rejection, named-route key checks,
batch output ownership and forbidden relay queries. The full transport suite has
Linux-only loopback and `/proc` assumptions and is assigned to Linux CI.

```sh
ctest --test-dir build --output-on-failure --no-tests=error \
  -R '^(test-json-rpc-(explorer|parse|account-capability)|test-pq-lite-forward-proof|control-getter-query-(service|boundary|admission|completion)|control-getter-budget|proof-readonly-query|block-signature-carrier-bound|pq-block-signature-conformance|pq-signature-tl-vectors)$'
build/test-json-rpc-transport --filter +explorer
build/test-json-rpc-transport --filter +proof_relay
TOS_EXPLORER_RPC_JOBS=1 build/test-json-rpc-explorer
TOS_EXPLORER_RPC_JOBS=8 build/test-json-rpc-explorer
python scripts/test-explorer-pq-rpc.py --out /tmp/explorer-v18
python scripts/test-explorer-pq-rpc.py --legacy-config --out /tmp/explorer-v16
uv run --with jsonschema==4.26.0 python scripts/validate-explorer-pq-receipt.py \
  /tmp/explorer-v18/*/rpc-evidence.json /tmp/explorer-v16/*/rpc-evidence.json
python scripts/test-explorer-pq-controls.py --out /tmp/explorer-controls
```

Run the two localnets sequentially: the fixture allocates additional per-node
port ranges. Fixture private keys, databases and verbose logs stay outside Git.
The live receipts contain public responses only. A compact evidence index is in
`test/pq-native/data/explorer-finality/validation-index.json`.

Five sensitivity controls independently remove full block-ID checking, exact
code identity, worker ownership, historical-session checking and backward-state
proof validation. Each must fail at its intended assertion and pass after byte
restoration. The frozen ordinary-predecessor proof and its manifest contain only
public TL proof material; the manifest pins its source and payload digests.

## Linux acceptance gates

`Explorer PQ two-build analysis` configures independent merge-base and candidate
builds, then runs `scripts/static-analysis.py` with CodeChecker 6.29.1 and LLVM
21.1.8. Its positive controls, compilation coverage and new-finding comparison
remain mandatory. The attempted local run proved all 10 positive controls but
refused the complete dependency scan on Linux-only `malloc.h`; refusal is not a
passing analysis result.

`Branch PQ chain and Python tests` builds the explorer regression target, runs
the full HTTP transport/native proofs, boots both VM versions and validates
actual response fragments against the reviewed schema. Public response receipts
are retained as CI artifacts for 14 days. `JSON-RPC ASan` covers the added native
explorer target. The normal strict native build also covers shared executor and
proof-validator changes. Relevant CI must pass before merge.
