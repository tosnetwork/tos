# BR1 native provider for local networks and an explicit testnet pilot

This ELF supplies the chain, signing and finality operations consumed by
`../native_adapter.py`. The default build is restricted to **global id 3**, global version16 or later,
a pinned zerostate and private Shield transfers. An explicit
`public-testnet-pilot` build additionally permits global-id2. This is a bounded
test-chain pilot capability, not production activation approval.

The local acceptance run uses four real validators, two observers and two
independently funded operators. It exercises HTTP quotes, real ML-DSA worker
signatures, audited Groth16 proofs, native transaction simulation, V3 wallet
submission, destination finality and encrypted commission-note import. Restarted
operators retain their original keys and journals. A further transaction spends
two actual commission notes through the other operator. Evidence indexes are
kept separately from seeds, raw transactions and logs.

## Build and custody

```sh
cargo build --release --locked --manifest-path tools/bonded-relayer/provider/Cargo.toml
cargo test --release --locked --manifest-path tools/bonded-relayer/provider/Cargo.toml
```

Install an owned, executable, non-writable copy of the resulting ELF and pin its
SHA-256 in the existing BR1 service configuration. The Python process boundary
executes a sealed snapshot. Its Linux Python runtime must provide `os.memfd_create`.
The provider also pins the locally installed `tos-proof-verify` ELF; the RPC
endpoint cannot select its verifier or trust anchor.

`--provision INPUT NEW_DIRECTORY` explicitly creates fresh local custody. The
owned 0600 input uses schema `tos.br1.provision.v1` and contains `global_id`,
`genesis_root`, `genesis_file`, `pool`, `pool_code_hash`, `pool_config_hash`,
`execution_domain`, `endpoint`, `fee`, `funding_cap`, `rpc_url`, `proof_verifier`
and `proof_verifier_sha256`. `proof_verifier` is the existing SDK configuration:
an absolute executable, anchor and lite-server configuration, a private live
state path, live age at most 60 seconds, timeout and query spacing.

Provisioning creates a 0700 directory, separate random worker/funding/fee-owner
seeds in 0600 files, a canonical Bond initialization and activation, V3 funding
wallet initialization, provider configuration and native lease journal. It
refuses an existing directory. No seed is accepted through arguments or the
environment. The receiving descriptor is derived from the fee-owner seed and
the pool's actual execution domain. Receiving indices are below `2^62`; custody
wallet change must use the disjoint higher range.

Fund and initialize the V3 wallet from the disposable local faucet. From the
private state directory, run `--bootstrap deploy-bond`, then
`--bootstrap activate-bond`, each once. They use the same native proven sequence
and durable one-send boundary as ordinary submissions. A transport acknowledgement
is explicitly **not** finality. The BR1 `--check` probe subsequently requires a
proven, backed active Bond and the correct funded wallet before service startup.
Missing or empty native databases refuse; they are never implicitly recreated
beside existing custody. Unknown outcomes require reconciliation of the original
bytes, not another setup invocation.

The runtime reads `provider.json` and its protected seed files from its private
working directory. The existing BR1 `localnet` configuration selects this ELF;
no fixture or unpinned manual broadcaster is used as a fallback.

## Verification and write ordering

* Account state comes from the established native proof verifier, with the
  configured genesis anchor and monotonic live checkpoint. Bond code, canonical
  identity, policy, worker key, backing and network are checked independently.
* Preflight executes the complete exact Shield candidate through the native
  compute **and action** phases. The complete configuration BOC obtained from
  RPC must hash to the execution configuration root authenticated by the proof
  verifier. Pool code/configuration, exact body, intent, nullifiers, expiry and
  decrypted fee output must agree. This is a local estimate, not future finality.
* Native sequence, acceptance slot and quote claims are durable before signing.
  An interrupted unsigned lease refuses replacement signing. The actual ML-DSA
  acceptance and V3 wallet bytes are persisted together before returning them.
  Validation checks the stored bindings, ED25519 wallet signature and contents,
  and independently verifies the ML-DSA acceptance and all its candidate fields.
* Recheck obtains current proven state and reruns the estimate. A five-second
  permit is consumed durably before the only possible RPC write. Consuming any
  permit also prevents a second permit from sending that lease. Timeouts remain
  unknown; there is no automatic resend or replacement signature.
* Finality walks transaction predecessor hashes from proven pool and wallet
  account heads. It links the exact prepared external message to the wallet's
  outbound message and the pool's successful inbound execution. The fee slot
  and leaf are reconstructed from that history, then decrypted and imported
  with the existing wallet ownership/body checks. Credit is idempotent by
  transaction/leaf and note identity. Stored ciphertext plus the custody seed
  can reconstruct the note without storing its plaintext secret in the ledger.

The native fee ledger records finalized imports, **not an unspent balance**.
Spending requires the wallet's ordinary history scan and nullifier reconciliation.
The local acceptance test performs that scan and actually spends imported notes.

## Bounds and remaining acceptance

Native requests/replies are bounded to 2 MiB, Shield body bytes to 256 KiB,
signed messages to 512 KiB and prepared metadata to 64 KiB. Parsed BOCs contain
ordinary level-zero cells only, at most 8,192 distinct cells and depth 256.
Custody operations are serialized across processes. The SQLite journal has a
4,096-page ceiling, retains at most 32 leases/imports and 64 permit tombstones,
and never evicts evidence to admit another request. Drain and rotate custody at
the first reached limit.

Finality acquisition is limited to 16 predecessor transactions per account and
2 MiB per RPC answer. Intervening successful deposits, transfers and reserve
top-ups have known leaf increments. Intervening bounces or unsupported mutations
refuse rather than guessing a leaf index. No terminal refusal is inferred from
expiry, an RPC error, a spent nullifier or source-wallet observation alone;
unavailable evidence remains unknown.

One terminal nonacceptance path is implemented for newly prepared messages.
Prepare retains the proven funding-wallet transaction head and logical time
before signing. After the signed wallet deadline, a native proven wallet state
must have the same sequence, head hash and logical time, and its **wallet shard
block time** must be at least the signed expiry. A newer masterchain timestamp
alone cannot close an older shard's acceptance window. The pinned V3 code
rejects expiry at or before its execution time. An unchanged head through that
window proves this exact external message was never accepted and cannot later
execute. Expiry or an RPC/source-wallet assertion by itself is insufficient.

The refusal receipt and its full public witness are retained atomically with
retiring the native lease and invalidating old permits. Old bytes, quote claims,
slots and replay tombstones remain. The existing terminal-refusal protocol then
releases the Python job's input locks without importing a fee. Retained receipts
are bounded to 16 KiB each and at most the 32 retained leases; they can be replayed
historically after later wallet activity, including while RPC is unavailable.
Legacy records without the pre-signing head, unsupported cache formats, changed
heads/sequences and shard states before expiry remain unknown. Never manufacture
a baseline from today's wallet state or reset custody to release a reservation.
A second terminal path authenticates an ordinary, non-destroyed destination
transaction with `aborted=true`. Its inbound must come from this funding wallet
and target the pinned pool. At the same proven checkpoint, the exact prepared
external wallet message must have executed successfully and emitted that exact
inbound message hash. A matching body sent by another wallet is skipped rather
than mistaken for this attempt. Aborted transactions advance no commitment
cursor and import no fee; successful attempts still require every execution
phase to succeed. The same atomic retirement/cache rules apply. Destruction,
unsupported descriptors or missing source links remain unknown.

The private native `pool_head` operation returns only the authenticated pool
head, state hash and checkpoint. The local history runner follows predecessor
hashes/LTs in bounded 16-row RPC pages to creation, optionally filling gaps from
retained archives. This diagnostic export does not enlarge the provider's
16-transaction finality window or authorize a transaction.

Real local-chain acceptance covers competing-spend refusal, a newer foreign
body replay, process death and retained-refusal recovery. Synthetic native C++
fixtures cover gas exhaustion (-14) and action failure (37), with successful
controls and state rollback; these are not on-chain gas/action fault injections.
The full C2 matrix remains open: on-chain forced gas/action failure, every
crash/write boundary, adversarial failover, Bond retirement/slashing,
privacy transport, production custody and economic/security review. The ordinary
private-transfer funding estimate is conservatively fixed at 0.25 local TOS and
must fit both request and operator caps. It is not a production pricing model.
No consensus, contract bytecode or chain configuration is changed by this provider.

The two local hardening follow-ups are addressed by the current implementation:

* **BR1-LOCAL-F01 (CK-6, PS-1):** recheck requires the signed wallet expiry to
  exceed the full five-second permit interval; broadcast checks expiry again
  before consuming the permit or writing to RPC. Historical signature validation
  remains independent of wall-clock time.
* **BR1-LOCAL-F02 (CK-7, CK-13):** the helper is opened once with no-follow flags,
  checked and hashed through that descriptor, copied into a bounded sealed memfd,
  and executed through its inherited descriptor. The snapshot stays open for
  the lifetime of the proof provider. Path replacement cannot change the executed
  release. Dynamic libraries remain part of the trusted host environment.


## Explicit public-testnet pilot (loopback only)

Build with `cargo build --release --locked --features public-testnet-pilot
--manifest-path tools/bonded-relayer/provider/Cargo.toml`. An ordinary build
continues to refuse global-id2. Every other global ID is refused in both builds.
The native provisioner validates the selected network **before** creating keys.
The Bond config, release and signed V3 wallet global ID all use that selection;
the V3 subwallet ID remains3. Genesis root/file and pool/Bond code/config pins,
authenticated config8/19 and full proof policy remain mandatory.

Provision **fresh test custody**, using the ordinary owned0600 provision template
with `global_id:2` and the independently authenticated public-testnet genesis,
pool/config and execution domain. Never copy localnet keys or fabricate an
anchor from an RPC assertion. Pin the feature-built ELF and proof helper hash.
No native test/provision command funds accounts, activates a Bond or broadcasts
a relay transaction. Bootstrap commands explicitly send and require a separate
live runbook step; never repeat one with an unknown result.

The Python entry point requires both `--testnet-pilot` and a private service
config with `schema:tos.br1.testnet-pilot.config.v1`, `mode:testnet-pilot` and
release global-id2. Other fields retain the local schema's exact shape. An
ordinary invocation accepts only localnet/id3; mismatched mode/network refuses.
Use `br1.py --config "$CONFIG" --testnet-pilot --check` before any listener. It
probes the actual pinned provider and continues to report
`production_approved:false`; missing/underfunded/unverified capability refuses.
The listener remains127.0.0.1 only. Reach it through existing authenticated SSH,
not a new Internet endpoint or a claim of anonymous public transport/discovery.

A pilot runbook must identify the reviewed heads/artifact hashes, independently
pinned genesis and pool, fresh custody and finite funding budget; current-term
and maintenance/soak clearance; read-only dry runs; one-shot funding/bootstrap
and a tiny private transfer; destination proof and real fee-note reconciliation;
and drain/unknown-result recovery. Enforce existing test budget/no refill and
never automatically re-sign or rebroadcast. Do not enable before applicable CI,
non-author/third-party review and local fault gates pass. The code capability
alone does not assert completion of full C2, production custody, economics,
privacy transport or independent security review.
