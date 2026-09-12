# PQ v16 readiness and account tooling

## What is implemented, and what is not an approval

This change provides a Rust implementation of the native ML-DSA-44 instruction,
real C++/Rust differential drivers, funded Wallet V5 / Agent Account deployment
and signing wrappers, a keystore adapter, explicit relayer attempt bookkeeping,
a native load runner, and a read-only activation proposal validator. It does not
activate a network, accept a loss model for an owner, or certify physical
validator hardware. Keep the integration in Draft until its final-head evidence
and the independent review are accepted.

The C++ software support ceiling is 16, and there is no build option that
selects another one: one source commit describes one binary capability. This
does not change ConfigParam 8, and a binary advertising 16 activates nothing.
The opcode still rejects global versions below 16. The separate Rust default configuration remains at its existing version;
explicit version selection is used in conformance tests. Matching one opcode is
not a claim of whole-VM or all intervening-version compatibility.

## Rust/native execution contract

`PQCHECKSIG_MLDSA44` is encoded as `F9 31 00`. The stack is message, context,
signature, key, with key at the top. The gate, stack underflow, base charge,
top-to-bottom type checks, ordinary level-zero cell loads and byte charges follow
the native implementation. The pinned portable C verifier is compiled into Rust
under a separate namespace; no provider selection, RNG, signing APIs or classical
signature-ignore flag is involved. Public keys are 1312 bytes, signatures 2420,
message at most 8192, and context at most 255. Non-final byte cells contain exactly
127 bytes; final empty padding and alternate cell types are refused.

The differential transcript includes exit, gas, boolean result, committed flag,
and c4/c5 hashes. It uses pinned NIST/independent vectors plus malformed cells,
stack/type errors, low gas, eleven paid calls, version rejection and canonical
partition tests. The comparison also requires independent expected verdicts;
two equally broken engines are not sufficient. Rust guard mutations must compile
and execute before a differing transcript counts as a kill.

That driver stops at the end of the compute phase, so `RAWRESERVE` and
`SENDRAWMSG` were only ever compared as an action-list hash.
`test/pq-readiness/tx_parity.py` closes that gap by running the same account and
the same inbound message through the native emulator and through
`tos_executor`, then comparing exit code, action-phase result, emitted message
hashes, balance and contract storage. Its four transactions are chosen so that
agreement means something: a verified request that is relayed, a tampered proof
refused at 1808, an expired request refused at 1805, and a request that verifies
but cannot pay for the forward, which succeeds in compute and fails in the
action phase with 37. A transcript missing any of those three outcomes is
rejected rather than reported, because two engines that refuse everything agree
perfectly.

## Build and test

```sh
scripts/install-rust-toolchain.sh
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build --target func fift tol emulator test-pq-v16-parity -j2
cmake -S crypto/pq/tools -B build-pq-key -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build-pq-key -j2
cargo build --manifest-path tosctl/src/Cargo.toml --locked --release -p tos_vm --example pq-parity
cargo build --manifest-path tosctl/src/Cargo.toml --locked --release -p tos_executor --example pq-tx-parity
cmake -S test/mldsa-auth -B build-auth-signer -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build-auth-signer -j2
python -m pip install bitarray==3.7.2 PyNaCl==1.5.0 pycryptodome==3.23.0 cryptography==46.0.4
python test/pq-mldsa44/prepare_vectors.py --out pq-results
python test/pq-readiness/scenarios.py pq-results/vectors.tsv pq-results/scenarios.tsv
build/crypto/pq/test-pq-v16-parity pq-results/scenarios.tsv > pq-results/cpp.tsv
tosctl/src/target/release/examples/pq-parity pq-results/scenarios.tsv > pq-results/rust.tsv
python test/pq-readiness/compare.py pq-results/scenarios.tsv pq-results/cpp.tsv pq-results/rust.tsv --out pq-results/parity.json
python test/pq-readiness/tx_parity.py --build build \
  --signer build-auth-signer/test-mldsa44-sign --out pq-results/tx-parity \
  --driver tosctl/src/target/release/examples/pq-tx-parity
python test/pq-readiness/test_sdk.py --build build --key-tool build-pq-key/tos-pq-key --out pq-results/sdk
python test/pq-readiness/test_controls.py
python test/pq-readiness/test_release_profile.py
```

## Relaying through a running chain

`contract.pq_lite_transport` reads its environment from a chain rather than a
constant: global id, global version, head, compute-gas prices from ConfigParam
20/21, message-forwarding prices from ConfigParam 24/25, account data, the
module's stored key, and the last transaction of both accounts. Compute quotes
use the same flat-gas-prefix formula as the chain. Forwarding quotes price the
actual AUTH envelope cell tree with the chain's lump/bit/cell prices; the larger
hybrid envelope is used conservatively when the mode is not an estimator input.
`WalletV5Signer` is the funding side of that loop. It reads the wallet's seqno,
wallet id and stored key from the account on every call and remembers nothing,
because signing for a seqno the wallet has already passed produces a message the
chain drops without a trace — which looks exactly like a lost broadcast. If the
seqno moved between the read and the signature, nothing is signed.

`deploy` funds a contract into existence and returns only once the account
carries the very data cell its address was derived from. Broadcasting is not
deployment, and an account that comes up with different data is a different
contract. `submit_internal` refuses when the funding wallet cannot pay, so the
relayer sees a refusal rather than a silent non-delivery, and refuses outright
when no wallet is attached.

`test/pq-readiness/test_lite_transport.py` covers the live-chain reads only when
`TOS_LITE_CLIENT` and `TOS_LITE_CONFIG` point at a node. The signing, funding,
fee-formula and deployment-confirmation paths do not need a node and always run.

`test/pq-readiness/live_relay.py` drives the whole loop on a chain that produces
blocks: it deploys a funding wallet by external message, deploys the module and
a PQ-only account by funded internal StateInit, relays an authorization, and
confirms the target received it and the nonce was consumed. It first submits a
proof with one flipped bit, which the module must refuse on chain without the
target moving and without the nonce being consumed; the nonce is then freed
through `retire` and reused for the real attempt. Finally the same authorization
is replayed and must be refused. Run it against the local chain from
`doc/macos-local-node.md`, started with `TOS_GLOBAL_VERSION=16`:

```sh
python test/pq-readiness/live_relay.py --build build \
  --lite-client build/lite-client/lite-client \
  --lite-config test/integration/.localnet-pq/lite-client.json \
  --key-tool build-pq-key/tos-pq-key --out pq-results/live
```

`test/pq-readiness/live_regression.py` covers the other axis on the same chain:
Wallet V5 and Agent Account, classical and post-quantum, eight cases. Four are
transfers that must arrive; four are refusals that must hold, because a run
where everything succeeds says nothing about whether a signature is checked. The
classical refusal is a structurally perfect message signed by a key the account
does not know -- the signed preimage is rebuilt so the message stays well
formed, and a refusal can only come from the signature check rather than from a
malformed file. The post-quantum refusal is a proof with one flipped bit, which
must be rejected on chain with the target unmoved and the nonce unspent, after
which `retire` frees the nonce for the real attempt.

Both controls were falsified against a running chain. Making the tampered
signer return the untouched signature stops the module rejecting anything and
the script fails where it waits for that rejection; signing the classical case
with the account's own key turns both refusal cases red, with the funds moving
and the sequence number advancing.

```sh
python test/pq-readiness/live_regression.py --build build \
  --lite-client build/lite-client/lite-client \
  --lite-config test/integration/.localnet-reg/lite-client.json \
  --key-tool build-pq-key/tos-pq-key --out pq-results/live-regression
```

Gas measured this way is the gas a production chain would charge, but the fee is
not: the local template in `test/tostester/src/tostester/zerostate.py` is marked
DEV-SPECIFIC and prices basechain gas 40 times below `gen-zerostate.fif`. Read
gas counts from a local run; convert them to fees with the target network's own
ConfigParam 21.

That first run is what found the receipt binding defect below. Both the module and the
account already have a last transaction before any attempt begins — their own
deployments — so a receipt that simply reads "the last transaction" reports the
account's deployment as this attempt's execution and claims a nonce was consumed
that never was. Receipts now ignore anything at or before the point the attempt
was prepared, and an attempt the module refused is never credited with an
account transaction at all, because the module forwards only what it accepted.

## Wallet and Agent wrappers

`tostester` exports WalletV5Blueprint, WalletV5, AgentAccountBlueprint,
AgentAccount, AgentPolicy, AuthState, AuthRequest, Mldsa44ModuleBlueprint and
NativeMldsa44Signer. Supply code from the compiled contract manifest; wrappers do
not silently embed old BOCs. Deployment produces a funded internal StateInit
message. The old external-empty deployment helper is explicitly refused for
these accounts. Sending the deployment is not confirmation: wait for the account
state and verify its code/data identity through the selected provider.

The tests deploy from a nonexistent account, rather than inserting an already
active fixture. They then execute classic, PQ-only and hybrid transfers using
SDK-produced messages in the native action-phase emulator. A successful account
outgoing transfer is not a claim that the recipient's transaction has run.

## Keys and relayers

`tos-pq-key keygen KEYFILE`, `public KEYFILE`, and
`sign KEYFILE MESSAGE_HEX CONTEXT_HEX` use the pinned signing implementation.
Key generation and randomized signing use the operating system-backed random
source. Private seed/key buffers are cleansed, key creation is exclusive, and
reads reject symlinks, wrong ownership, broad permissions and incorrect length.
The Unix adapter stores an **unencrypted 32-byte seed** in an owner-only file. It
is not a hardware wallet, encrypted vault, recovery service or audited keystore.
Back it up securely or implement the PqSigner interface with an approved keystore.
Production keys must never be copied from the public test fixtures.

PqRelayer requires a RelayTransport that supplies validated current chain state,
actual fee estimates and transaction receipts. It checks network, version, root,
epoch, nonce, expiry margin, key and mode before signing. FundingBudget separately
accounts for module compute, forwarding, account execution and margin under an
explicit cap. The caller must provide the exact LOSS_ACK string; no default
acceptance is supplied. SQLite reserves an account/epoch/nonce before broadcasting.
A timeout stays unknown; restart does not permit a blind duplicate. Reconciliation
requires request/module/account identity and distinguishes pending, module
rejection, account rejection and committed execution. These local controls do not
eliminate races with independent relayers.

The transport is an interface, not a new unauthenticated JSON-RPC service. A
production deployment must connect it to its trusted provider and fee-estimation
policy. No automatic retry after uncertain delivery, refund promise or owner
approval is included.

## Load and activation

`tools/pq/load.py` runs bounded concurrent batches of actual native VM executions
including valid, invalid, maximum-message and malformed inputs. It records machine
metadata, binary/workload hashes, CPU time, p50/p95/p99, gas and an explicit latency
budget. It labels its output `native-emulator-load`, never `production-validator`.
CI uses this as a smoke/load regression, not a production throughput claim.

Production qualification must additionally measure collator/validator block
execution, hostile mixed workloads, message/state sizes, scheduling, memory,
network propagation and finality on the intended slowest supported hardware.
Operators own the tested block gas limits, hardware inventory, latency budgets
and signed release approval. Reprice before activation if CPU/gas cost is unsafe.

`tools/pq/activation.py MANIFEST --out PROPOSAL` validates a v15-to-v16 proposal.
Every configured validator must acknowledge the same release commit, explicitly
identify the `pq-v16-candidate` build profile, and bind that acknowledgement to a
64-hex SHA-256 digest of the concrete binary it will run. A source commit alone
is insufficient because the same tree deliberately builds both default-v15 and
candidate-v16 binaries. The production-load report must qualify an acknowledged
candidate binary; CI-only load evidence is refused. Four explicit owner/operator
approvals must exist, and all five evidence files — opcode parity, whole
transaction parity, module end-to-end, production load and activation rehearsal
— must match their hashes, network applicability and release. The output preserves
capability bits and provides an **unsigned Config8 payload**, never a signed update.
The roster and evidence's truth still need independent verification; a local
manifest is not a cryptographic attestation. Follow the network's actual approved
configuration procedure, not an invented block-height switch. No automatic
downgrade is safe after v16 transactions have been accepted.
