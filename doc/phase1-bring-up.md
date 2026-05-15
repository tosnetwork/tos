# Phase 1 — Closed Testnet Bring-Up Guide

> **Audience**: the launch coordinator + the 5–10 operators
> running the initial closed testnet validators.  This is the
> operational handover document from the engineering arc (Phases
> O–FF) to the testnet phase of `doc/mainnet-readiness-checklist.md`.
>
> **Scope**: closed testnet, ~5–10 validators, invited developers
> trying to break it.  Public testnet is Phase 2 (separate doc).
>
> **Time budget**: 4–6 weeks of operation.  Don't shorten it.

---

## 0. Pre-requisites

Each operator (validator + coordinator) needs:

* Ubuntu 22.04 LTS server (or arm64 equivalent — Phase AA proved
  rt.jar reproducibility across both)
* 8+ CPU cores, 32 GB RAM, 1 TB NVMe (matches §2 of
  `jvm-validator-ops.md`)
* Public IPv4 + ports 30303 (TCP+UDP) reachable
* `openjdk-8-jdk-headless`, `python3`, `make`, `git`, `cmake` installed
* Optionally: Docker (Phase Z canonical-build image)

The coordinator additionally needs:

* A secure machine to run the genesis ceremony (the keypairs you
  generate here are testnet-only but treat them as if they were
  mainnet — practice the discipline)
* Ability to publish artifacts (rt.jar bytes, canonical hash,
  zerostate BOC) to all operators

---

## 1. Coordinator side: prepare the launch package

### 1.1 Build the canonical rt.jar

Either via the CI workflow (`.github/workflows/check-jvm-rt-determinism.yml`)
or locally under the canonical toolchain:

```bash
# Local build (requires Ubuntu 22.04 + openjdk-8-jdk-headless)
make -C jvm/avata java-version=8 check-rt-jar-determinism
# Should print: OK: rt.jar sha256 stable across two clean builds = <hex>

# Capture the canonical stdlib_hash
export STDLIB_HASH=$(make -s -C jvm/avata java-version=8 print-rt-jar-stdlib-hash)
echo "canonical stdlib_hash = $STDLIB_HASH"
```

Distribute to every operator:

* `jvm/avata/build/linux-x86_64/rt.jar` (or `linux-arm64/rt.jar`)
* The canonical `STDLIB_HASH` value
* The git commit SHA the binary was built from

### 1.2 Collect operator public keys

Each operator generates an Ed25519 keypair for:

* **Validator identity**: signs catchain consensus messages
* **One Wallet**: pre-funded testnet account
* **One Deployer** (optional): if the operator will also be a
  deployer-of-contracts

The Phase X rehearsal script
(`scripts/jvm-testnet-genesis-rehearsal.sh`) uses deterministic
test keypairs.  For a real closed testnet, each operator should
generate their own via:

```bash
# Each operator runs locally
tosctl jw create --name my-testnet-wallet  # see jvm-validator-ops.md
# Sends the resulting pubkey to coordinator
```

Coordinator collects:

```text
operator-id | validator pubkey (32B hex) | wallet pubkey | deployer pubkey
op-01       | 0xa1...                    | 0xb1...        | 0xc1...
op-02       | 0xa2...                    | 0xb2...        |  (none)
...
```

### 1.3 Build the canonical genesis

Edit `crypto/smartcont/jvm-testnet-rehearsal.fif` (or a copy)
substituting the operator-supplied pubkeys for the deterministic
fixtures.  Then run the rehearsal script:

```bash
scripts/jvm-testnet-genesis-rehearsal.sh
```

Capture the printed `jvmstate3 root hash` and `file hash`.  These
go into ConfigParam 12 alongside the other workchains.

For the full multi-workchain zerostate:

```bash
FIFTPATH=$PWD/crypto/fift/lib:$PWD/crypto/smartcont \
  build/crypto/create-state crypto/smartcont/gen-zerostate.fif
# Produces: basestate0.boc, evmstate1.boc, unostate2.boc, jvmstate3.boc
# Plus: zerostate.boc (the masterchain commitment)
```

Distribute to every operator:

* `zerostate.boc` (the canonical genesis)
* All per-workchain `*state*.boc` files
* Their root + file hashes (for cross-verification)

### 1.4 Configure ConfigParam 85

ConfigParam 85 carries `stdlib_hash` for wc=3 admission.  In the
zerostate Fift script, ensure:

```fift
{ open file rt.jar } file>B
jvm-config-param-cell-with-stdlib
85 config!
```

(See `crypto/block/create-state.cpp:976` for the binding.)

The validator's runtime will hash its loaded rt.jar at startup
and compare against this value (Phase DD canonical algorithm —
domain-tagged sha256).  Mismatch → every wc=3 tx rejects.

---

## 2. Operator side: bring up the validator

### 2.1 Download canonical artifacts

From the coordinator (out-of-band — direct download, gpg-signed
release, or similar):

```bash
# Verify rt.jar hash matches the coordinator's published value
LOCAL_HASH=$(python3 jvm/avata/tools/compute-stdlib-hash.py rt.jar)
if [ "$LOCAL_HASH" != "$COORDINATOR_HASH" ]; then
  echo "FATAL: rt.jar hash mismatch — refusing to start"
  exit 1
fi
```

### 2.2 Place rt.jar at the canonical path

The validator looks for rt.jar at the path baked into the binary
at build time (`TOS_AVATA_DEFAULT_RT_JAR`), or honors the
`TOS_JVM_AVATA_RT_JAR` env var (see `jvm-validator-ops.md §3.1`):

```bash
# Option A: baked-in path (if you built locally)
# Nothing to do — the path matches the build tree

# Option B: env var override (recommended for production)
export TOS_JVM_AVATA_RT_JAR=/opt/tos/rt.jar
```

### 2.3 Initialize the validator

```bash
sudo scripts/setup-testnet.sh
# Brings up dht-server + 3 local validators using the existing
# tostester infra.  For multi-host Phase 1, mirror the per-host
# config from a single template.
```

> **Note**: `setup-testnet.sh` predates the wc=3 work and configures
> wc=0/1/2 only.  Phase 1 operators add wc=3 by:
>
> 1. Copying the wc=3 ShardState from the coordinator's zerostate.boc
> 2. Editing the per-validator config to opt into wc=3
> 3. Setting `TOS_JVM_AVATA_RT_JAR` in the validator-engine env
>
> See `jvm-validator-ops.md §4` for the wc=3 opt-in details
> (some fields are marked TBD pending the exact validator-engine
> config schema landing).

### 2.4 Verify the cluster

After all operators have started their validators:

```bash
# Coordinator runs from one validator
tosctl get-config 85    # should print the canonical stdlib_hash
tosctl get-config 12    # should list workchains 0, 1, 2, 3

# Verify the local validator's runtime rt_jar_hash matches
# ConfigParam 85.  If it doesn't, the validator can't process
# wc=3 transactions:
journalctl -u tos-validator@1 | grep -i "rt_jar_hash\|stdlib_hash"
```

A healthy startup log includes:

```
register_jvm_workchain_engine: installed wc=3 compute path
WorkchainExecutionRegistry: resolved wc=3 descriptor (vm_version=0x4a564d31)
ConfigParam 85: stdlib_hash=ae4ff3b7e557a8acffe31e9b41959e811c67dea87b6c6c3e38129466e5ade765
```

(The hash above is the Phase-DD canonical for HEAD `58a2b7292`;
your value depends on the commit you built from.)

---

## 3. Phase-1 test plan

Once the cluster is up, invited developers exercise the chain
with the following scenarios.  Each one should produce a
documented result (success / failure / surprise).

### 3.1 wc=3 happy path

1. Create a wc=3 wallet via `tosctl jw create`.
2. Verify the wallet's address matches what off-chain derivation
   computes (parity sanity check).
3. Use a Deployer (genesis-seeded) to deploy the same Wallet at
   that address.
4. Send a Wallet.execute transfer to another wallet.
5. Verify the recipient balance updated.
6. Query receipts via `tosctl jw receipts`.

Expected: all of the above complete in 1–2 blocks.

### 3.2 wc=3 contract deploy (generic)

1. Author a simple counter contract (Counter.java) with
   `init(uint256)`, `increment()`, `getValue()` methods.
2. Build the `.class` file (operators may use the Phase Z
   Dockerfile to compile).
3. Write a manifest JSON listing the methods.
4. Deploy via `tosctl jw deploy-contract --class-file Counter.class
   --manifest-file counter.json --salt 0x... --init-arg uint256:0
   --via my-deployer`.
5. Call `increment()` via `tosctl jw call --contract <addr>
   --method "increment()" --via my-wallet`.
6. Verify the value increments.

Expected: deploy + call complete; event receipts visible.

### 3.3 Adversarial scenarios for the invited developers

Encourage attempts to:

* **Re-use a Wallet nonce** → must reject with `Wallet_BadNonce`
* **Forge a Deployer signature** → `Deployer_BadSignature`
* **Deploy a contract with mismatched stdlib_hash** → `sk_bad_state`
* **Deploy a contract whose JVAC doesn't address-bind** → `sk_bad_state`
* **Spam jvm_callContract with bad inputs** → caps enforced
  (see `jvm-dos-hardening.md`)
* **Emit unlimited outbound actions from a single tx** → caps at 12
* **Try to fork the chain** (run a stale binary on one validator) →
  Phase R determinism gate must catch
* **Send a deeply-nested cell to the RPC** → BOC parse caps
* **Network partition a single validator** → catchain recovery

Document every interesting interaction in the bug log (§4 below).

### 3.4 Multi-validator stress

Once basic happy paths work, drive sustained load:

1. 100 wc=3 contract deploys
2. 10K wc=3 method calls across them
3. Monitor: gas-used percentiles, dispatch error rate, block
   production cadence, memory usage on each validator
4. Compare ShardAccounts dict root hash across all validators
   after each block — they MUST match

Document any divergence (which is a P0 finding) immediately.

---

## 4. Bug log

See [`phase1-bug-log-template.md`](phase1-bug-log-template.md).
File every finding there — including ones that "look minor."  The
goal of Phase 1 is to surface everything before Phase 2 (public)
sees it.

Severity ladder for testnet bugs:

| Sev | Definition | Action |
|---|---|---|
| **P0** | Consensus divergence; data loss; validator crash; sk_bad_state on a should-work tx | Halt testnet; fix; relaunch |
| **P1** | Wrong result on a documented happy path; DoS surface | Fix before continuing; no halt |
| **P2** | UX issue; doc gap; surprising-but-correct behavior | Track, batch-fix |
| **P3** | Cosmetic; observability gap | Track for Phase 2 |

---

## 5. Phase-1 exit criteria

Phase 1 is "done" when:

* [ ] Validators have been running continuously for ≥4 weeks
* [ ] At least 3 weeks of that overlapped with active developer
      attacks (not just idle)
* [ ] All P0 / P1 findings closed
* [ ] No new P0 / P1 findings in the most recent 2 weeks
* [ ] Multi-validator stress test sustained target TPS for ≥1
      hour without any cross-validator divergence
* [ ] Genesis ceremony rehearsal has been re-run after the
      final code freeze and the canonical hashes match

Once those are checked, transition to Phase 2 — public testnet +
external audit in parallel (see §4 of
`mainnet-readiness-checklist.md`).

---

## 6. Where to look for help

| File | What's there |
|---|---|
| `doc/jvm-validator-ops.md` | wc=3 operator runbook (some TBDs noted) |
| `doc/jvm-rt-reproducibility.md` | rt.jar build + canonical hash |
| `doc/jvm-dos-hardening.md` | All known caps + tests + audit checklist |
| `doc/jvm-mainnet-activation.md` | Genesis ceremony (rt.jar + ConfigParam 12/85) |
| `doc/jvm-wallet.md` | java.lang.Wallet semantics |
| `doc/jvm-rt.md` | rt.jar admitted contracts |
| `scripts/jvm-testnet-genesis-rehearsal.sh` | Single-keypair rehearsal |
| `scripts/setup-testnet.sh` | Existing wc=0/1/2 local-cluster bring-up |
| `doc/mainnet-readiness-checklist.md` | The honest full assessment |

When stuck: the audit memories under
`~/.claude/projects/-home-tomi-tos/memory/` capture decisions +
the rationale behind them.

---

## 7. Mantra

**The point of Phase 1 is to find bugs the engineering audit
couldn't.**  Every issue logged here is an issue that doesn't
ship to Phase 2 (public).  Every issue that ships to Phase 2 is
an issue that doesn't ship to mainnet.  This is the cheapest
filter in the entire pipeline.

Don't be tempted to skip it.  No serious chain has launched
mainnet without an analogous closed testnet, and the ones that
tried have post-mortems.

Phase DD (the consensus bug Phase EE locked) is a concrete
example: a critical bug that no amount of code review found,
and that this Phase-1 testnet would have surfaced within minutes
of the first wc=3 call.
