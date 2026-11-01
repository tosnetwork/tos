# BR1 native provider for an isolated local network

This ELF supplies the chain, signing and finality operations consumed by
`../native_adapter.py`. It is restricted to **global id 3**, global version 16
or later, a pinned zerostate, and private Shield transfers. It is not a public
testnet deployment or production activation approval.

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
unavailable evidence remains unknown. This increment does not yet supply every
terminal-refusal/liveness path.

The full C2 matrix remains open: forced gas/action failure, every crash/write
boundary, adversarial failover and refusal recovery, Bond retirement/slashing,
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
