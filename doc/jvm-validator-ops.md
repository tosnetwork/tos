# JVM (wc=3) Validator Operations Runbook

> **Status**: draft for testnet launch.  Mirrors the structure of
> [`doc/uno-v1-validator-ops.md`](uno-v1-validator-ops.md).  Several
> concrete commands and metric names below are marked **TBD** —
> they depend on shipped binary surfaces still landing.  Where TBD,
> the cited source file is the current truth.

---

## 1. Scope and audience

This runbook is for a **TOS validator operator** already running a
healthy TOS validator on `wc=0` (and optionally `wc=1` / `wc=2`)
who wants to **opt into `wc=3` (JVM)**.  It does not cover
first-time TOS validator setup — that lives in
[`doc/Validator.md`](Validator.md) and
[`doc/Validator-Local.md`](Validator-Local.md).

JVM does not add a separate node binary: the same
`validator-engine` picks up `wc=3` once the engine registration is
linked in and ConfigParam 12 + ConfigParam 85 are present
(`jvm/core/init.cpp` installs the `wc=3` compute handler alongside
EVM / UNO).  Expected reader skill: Linux operator comfortable
with `systemd`, `journalctl`, Prometheus/Grafana, and the existing
`validator-engine` configuration surface.

---

## 2. Hardware specification (testnet baseline)

### 2.1 Minimum

| Resource  | Value                                          |
|-----------|------------------------------------------------|
| CPU       | 4 physical cores (x86_64 AVX2 or ARM v8)       |
| RAM       | 16 GB                                          |
| Storage   | 1 TB NVMe SSD (+ ~50 GB/year wc=3 growth at testnet load) |
| Network   | 50 Mbps sustained / 100 Mbps burst, symmetric  |

Rationale:

- **CPU** — Avata interpreter is single-threaded per call; the
  validator-engine runs N parallel workers (one per shard / wc).
  ConfigParam 85 caps gas-per-tx at 1 M which translates to ~50 ms
  typical wall-time per wc=3 tx on modern hardware.  4 cores clear
  the 1 s block budget with ample headroom at the expected testnet
  TPS.
- **RAM** — JVM heap is per-account, capped at 4 MiB
  (`max_heap_bytes` in ConfigParam 85).  Per-class bytecode is
  deduplicated via Cell DB (`MultiContractIsolatedStorageWithShared
  Class` test pins this property), so 1000 instances of the same
  contract cost ~1× the class size, not 1000×.  16 GB hosts comfortably
  hold the rt.jar + thousands of distinct contract classes + the
  in-flight call working set.
- **Storage** — each wc=3 account is one `Account` cell carrying
  one JVAC ref.  JVAC body is the storage_root dict
  (per-account state) + the class_bytes ref (deduped).  Per-account
  growth dominated by storage_root mutations; modest contracts add
  KB-scale deltas per call.
- **Network** — wc=3 ext-in / int-out messages carry call
  descriptors (typically <1 KB) + event emissions (variable but
  capped by `kJvmReceiptResponseByteBudget = 1 MiB` per
  `jvm_getReceipts` page).  Bandwidth is not the binding constraint
  at testnet TPS.

### 2.2 Recommended

| Resource  | Value                                          |
|-----------|------------------------------------------------|
| CPU       | 8+ cores                                       |
| RAM       | 32 GB                                          |
| Storage   | 2 TB NVMe SSD                                  |
| Network   | 100 Mbps sustained                             |

Headroom for the rt.jar contract library to grow, and for the
JVM-emitted event indexing if running an explorer alongside the
validator.

---

## 3. Software prerequisites

### 3.1 Pinned rt.jar

The validator MUST agree with every other wc=3 validator on the
exact `rt.jar` bytes the chain admits.  ConfigParam 85 carries the
sha256 of this archive (`stdlib_hash`); validators reject every
wc=3 transaction whose JVAC's `stdlib_hash` field doesn't match.

For a public testnet bring-up:

1. The launch coordinator builds rt.jar from a pinned tree commit
   (`jvm/avata/makefile`'s `build-rt-jar` target).  See
   [Phase V — rt.jar reproducible build](#) when that work lands;
   until then, treat rt.jar as a binary artifact distributed by
   the coordinator.
2. The coordinator publishes the rt.jar bytes + its sha256 in the
   testnet release notes.
3. Operators download the rt.jar, verify the sha256, place it at
   the path the validator-engine expects (TBD — currently the
   path is baked into the build; see
   `jvm/core/config-param.cpp:285` for where `stdlib_hash` is
   pinned).
4. ConfigParam 85's `stdlib_hash` must equal the same sha256.
   Operators participating in genesis sign the masterchain
   zerostate that carries this value; operators joining post-
   genesis inherit the value from the on-chain config.

A mismatch produces `sk_bad_state` on every wc=3 inbound call.
See §6 troubleshooting.

### 3.2 Native crypto libraries

The wc=3 compute path relies on libsodium (Ed25519), libsecp256k1
(secp256k1 ECDSA + recover), and blst (BLS12-381) being available
as link dependencies of `validator-engine`.  All three are
vendored under `third-party/` and built statically; an operator
building from source needs the usual system toolchain (autotools,
cmake, ninja).  No external runtime libraries.

### 3.3 ConfigParam 12 + ConfigParam 85

For wc=3 to be admissible at all, both must be present in the
masterchain config:

* **ConfigParam 12** — the WorkchainSet — must carry a `wc=3`
  entry built by `add-jvm-workchain` (Fift) /
  `jvm_workchain::build_jvm_workchain_descr` (C++).  See
  [`doc/jvm-mainnet-activation.md`](jvm-mainnet-activation.md) §4
  for the launch flow.

* **ConfigParam 85** — the JVM activation config — carries
  `stdlib_hash`, gas schedule, opcode costs, max_class_bytes,
  max_heap_bytes.  Built by `jvm-config-param-cell-with-stdlib`
  (Fift); see [`doc/jvm-mainnet-activation.md`](jvm-mainnet-activation.md) §5.

If either is absent, `register_jvm_workchain_engine` still
installs the engine but `WorkchainExecutionRegistry::resolve`
returns `not found` and the validator silently drops wc=3 traffic.

---

## 4. Enabling wc=3 on your node

> **TBD on exact CLI surface** — the existing TOS validator config
> already supports per-workchain opt-in via the validator-engine
> JSON config.  The fields below are inferred from `wc=1` (EVM)
> and `wc=2` (UNO) precedents; consult `validator-engine/`'s
> config schema for the exact flag names.

### 4.1 Verify the engine is linked

```bash
$ /usr/bin/validator-engine --version 2>&1 | grep -i jvm
```

If the build was compiled without `-DTOS_BUILD_WC_JVM=ON` the
binary will not have the JVM compute path linked and wc=3 traffic
will be ignored.

### 4.2 Opt in via local config

Edit your validator-engine config and add `3` to the
`workchains` array (or equivalent; check your distribution's
config wrapper).  Restart the validator:

```bash
sudo systemctl restart tos-validator
sudo journalctl -u tos-validator -f | grep -iE "jvm|wc=3"
```

Expected boot log lines:

```
register_jvm_workchain_engine: installed wc=3 compute path
WorkchainExecutionRegistry: resolved wc=3 descriptor (vm_version=0x4a564d31)
ConfigParam 85: stdlib_hash=<32-byte hex>
```

If any of those are missing, double-check §3.3.

### 4.3 Sync from peers

On first activation the node fetches the wc=3 ShardState from a
peer and starts validating.  Sync time is bounded by the wc=3
account count + transaction history depth; expect 5–30 minutes on
a freshly-launched testnet.

---

## 5. Monitoring

### 5.1 Metrics (Prometheus)

> **TBD on exact metric names** — the metric registration patterns
> exist on `wc=0` / `wc=1`; the wc=3 entries follow the same
> conventions.  Suggested keys:

| Metric                              | What it measures                  |
|-------------------------------------|-----------------------------------|
| `tos_wc3_blocks_processed_total`    | Blocks the local node validated  |
| `tos_wc3_transactions_total{result=...}` | wc=3 tx counts split by result |
| `tos_wc3_compute_gas_used_seconds` | Histogram of gas-used per tx     |
| `tos_wc3_dispatch_errors_total{kind=...}` | sk_bad_state, sk_out_of_gas, sk_bad_signature, etc. |
| `tos_wc3_message_host_actions_total{kind=send|create_account}` | Outbound action emission count |
| `tos_wc3_storage_cells_live`        | Per-account storage cell footprint |
| `tos_wc3_rpc_get_receipts_truncated_total` | Times `jvm_getReceipts` hit its cap |

### 5.2 Logs to alert on

```
ERROR  dispatch-engine: sk_bad_state  ← stdlib_hash mismatch or JVAC drift
ERROR  message-host: oversized state_init  ← contract emitted >max-bytes state
ERROR  avata-runtime: contract revert (Wallet_BadSignature)  ← op-side; not a node bug
ERROR  json-rpc-server-jvm: byte budget exceeded  ← noisy contract; not a node bug
```

The first two are node-level invariants — if either fires
sustained, the node will fall out of consensus and should be
investigated immediately.  The latter two are contract-side
issues that the node correctly diagnoses; operators don't need to
page on them.

### 5.3 Grafana panel suggestions

* TPS on wc=3 vs other workchains (sanity: wc=3 should NOT spike
  faster than its gas-cap allows).
* Gas-used percentile (50 / 95 / 99); spikes above max_gas_per_tx
  imply a contract approaching the cap.
* Dispatch-error breakdown by kind (any persistent non-zero
  `sk_bad_state` rate suggests state corruption or stdlib_hash
  drift).
* `jvm_getReceipts` response sizes (catches a contract emitting
  events that approach the byte budget).

---

## 6. Common failure modes

### 6.1 `sk_bad_state` on every wc=3 call

**Symptom**: every wc=3 inbound message rejected in compute_phase
with `skip_reason == sk_bad_state`.

**Causes** (in order of likelihood):

1. **stdlib_hash mismatch** — the JVAC's `stdlib_hash` field
   doesn't equal ConfigParam 85's `stdlib_hash`.  Either the
   contract was deployed with the wrong hash (operator-side bug;
   the offending deploy tx is the root cause) or the node's
   ConfigParam 85 disagrees with the chain.  Run `tosctl get-config
   85` and compare against the value the contract baked in.

2. **Address-binding gate mismatch** — the JVAC's recomputed
   address doesn't equal `input.account_addr`.  This is consensus-
   fatal: if a Deployer.deploy() produced an account whose binding
   doesn't hold, every subsequent call rejects.  Phase Q's
   `WalletDeploymentLifecycleEndToEnd` test pins the binding round-
   trip and should catch this in CI; if it surfaces in production
   it means some component is emitting a non-binding JVAC.

3. **Manifest drift between off-chain CLI and on-chain
   admission** — `tosctl jw deploy-contract`'s manifest cell hash
   must equal what the rt.jar admits.  See Phase J / N parity
   vectors in `jvm/core/jvm-codec-reference.txt`.

### 6.2 `sk_out_of_gas` on legitimate-looking calls

**Symptom**: a call that compiled and worked locally aborts with
`sk_out_of_gas`.

**Causes**:

1. The call ran into the ConfigParam-85 `max_gas_per_tx` cap.
   Either reduce the work the call does, or for testnet, the
   coordinator can bump the cap (governance-only on mainnet).

2. The activating call body's args triggered the helper-gas table
   in an unexpected place (e.g., a large `keccak256` of variable-
   length data scales linearly).  Check `tos_wc3_compute_gas_used_seconds`
   histogram around the failure.

### 6.3 `Wallet_BadSignature` from a fresh deploy

**Symptom**: `tosctl jw execute` calls reject with
`Wallet_BadSignature`.

**Causes**:

1. **Wrong nonce** — the wallet's on-chain nonce advanced from
   another caller.  Re-fetch via `tosctl jw info` and retry.

2. **Address-binding mismatch** between off-chain signer and on-
   chain wallet — `compute_wallet_execute_digest` (Rust) and
   `Wallet.digest()` (Java) must agree on the digest input.  This
   is locked by Phase M parity vectors; if drift surfaces it's a
   CI-failure-grade bug.

### 6.4 `validator-engine` won't start

**Symptom**: the validator process exits during boot with a
ConfigParam parse error.

**Cause**: ConfigParam 85 cell shape doesn't match the
`JvmConfig` decoder.  Re-run the genesis Fift script with the
correct `stdlib_hash` and confirm the cell deserializes via
`tosctl get-config 85`.

---

## 7. Upgrade procedure

### 7.1 rt.jar upgrade (consensus-stable)

Upgrading rt.jar changes `stdlib_hash` and is therefore a
hard-fork-class change: every wc=3 contract's JVAC carries the
old hash, so the new rt.jar would `sk_bad_state` everything.  The
launch coordinator handles this via either:

* **Phased rollout**: bump `stdlib_hash` in ConfigParam 85
  alongside a re-admission step that re-anchors every existing
  contract.  Not implemented in v1; defer until needed.

* **Sticky rt.jar**: keep the rt.jar pinned for the life of the
  chain.  This is the v1 testnet policy — any rt.jar evolution
  ships as a v2 chain rather than mutating v1.

Operators do not unilaterally upgrade rt.jar; doing so falls them
out of consensus immediately.

### 7.2 validator-engine binary upgrade

Standard `systemctl restart tos-validator` after replacing the
binary.  The wc=3 path has no migration state — it picks up the
on-chain ConfigParam 85 on boot.

### 7.3 ConfigParam 85 governance update

Non-`stdlib_hash` fields (gas schedule, max_gas_per_tx, helper-gas
table) can be updated via the normal config-vote machinery.
Tooling: `tosctl create-config-proposal 85 <new-cell>` →
governance vote → apply.

---

## 8. Disaster recovery

### 8.1 Local DB corruption on wc=3 only

`tos-validator` keeps per-workchain DBs.  If only wc=3 shows
checksum errors, the recovery is:

1. Stop the validator.
2. Delete the wc=3 DB directory (TBD path — see your distribution).
3. Restart; node re-syncs wc=3 from peers.

The catchain state is shared across workchains so this is a
recoverable workchain-local action, not a full-node rebuild.

### 8.2 Fork on wc=3

If your node disagrees with the rest of the network on a wc=3
block hash, the protocol-level outcome is the same as on any
other workchain: the local node falls out of consensus on that
shard and the catchain protocol's recovery applies.

Specific things to check before assuming a bug:

* ConfigParam 85 `stdlib_hash` matches the network's value.
* The rt.jar bytes on disk hash to the value in §3.1.
* No locally-applied patches to `jvm/core/` or `jvm/avata/`.
* Re-run the test suite: `./test-workchain-execution-registry`
  should print "114 test(s) passed" (the wc=3 invariant set).

If everything checks out and the fork persists, escalate to the
launch coordinator with the wc=3 block hash where divergence
started.

---

## 9. References

| Document                                                            | Topic                                  |
|---------------------------------------------------------------------|----------------------------------------|
| [`doc/jvm-mainnet-activation.md`](jvm-mainnet-activation.md)         | Genesis ceremony, ConfigParam 12 + 85 |
| [`doc/jvm-v2-account-topology.md`](jvm-v2-account-topology.md)       | Per-account JVAC, address binding     |
| [`doc/jvm-wallet.md`](jvm-wallet.md)                                 | java.lang.Wallet semantics            |
| [`doc/jvm-rt.md`](jvm-rt.md)                                         | rt.jar admitted contracts             |
| [`doc/jvm-profile.md`](jvm-profile.md)                               | Verifier profile, allowed opcodes     |
| [`doc/jvm-roadmap.md`](jvm-roadmap.md)                               | Phase log + known gaps                |
| [`jvm/avata/`](../jvm/avata/)                                        | Avata JVM interpreter sources         |
| [`jvm/core/`](../jvm/core/)                                          | TOS-side compute/dispatch path        |

---

## 10. Open items

These remain TBD at testnet bring-up and will be filled in
post-launch based on operator feedback:

* Exact metric names (§5.1) — emitted from `validator-engine`
  Prometheus exporter once instrumentation lands.
* Per-distribution path for rt.jar (§3.1) and wc=3 DB (§8.1).
* Exact systemd unit name + config schema field names for opting
  into wc=3 (§4).
* Multi-validator stress-test results to calibrate the TPS /
  hardware guidance (§2).

Updates land in this file as the surfaces stabilize.
