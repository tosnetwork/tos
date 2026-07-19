# Genesis Validator Bootstrap (`validator-keys.pub`)

How to seed the **initial validator set** of a TOS network at genesis — the
validators that run the chain *before* the first staking election.

AI actor launch plans should treat this as validator bootstrap only. Agent,
task, service, and verifier accounts should be deployed through auditable
native transactions or explicitly documented genesis allocations.

If genesis allocation is used for AI actor bootstrap, the launch plan must
document:

- recipient address
- intended actor type
- initial balance
- controller or owner authority
- whether the account is predeployed or funded for later deployment
- rollback or recovery policy before public use

## TL;DR

- **Genesis validators do not stake.** They are written directly into the
  zerostate (ConfigParam 34) with a fixed weight. No TOS balance is required to
  be a genesis validator.
- Staking (`min_stake`, currently **10,000 TOS** — see
  [ConfigParam.md §17](ConfigParam.md)) is only needed **later**, when the
  `elector` contract runs the first on-chain election that replaces the genesis
  set. Those stakes come from the **5,000,000 TOS pre-mined to the main wallet**
  (see [Zerostate.md §Initial Token Supply](Zerostate.md#initial-token-supply-per-workchain-issuance)),
  distributed to candidates by the launch operator.
- The genesis set is injected from a file called **`validator-keys.pub`** — a
  flat concatenation of 32-byte raw Ed25519 public keys. The native
  `gen-zerostate*.fif` flow reads this file directly during zero-state
  construction.

## Background: why no stake at genesis

A chain cannot run its first staking election before it produces any blocks, and
it cannot produce blocks without validators. TOS breaks this bootstrap loop by
appointing the **first** validator set in the zerostate before later handing
control to on-chain elections.

In `crypto/smartcont/gen-zerostate.fif`:

```fif
{ file>B { dup Blen } {
    32 B| swap dup ."Validator public key = " Bx. cr
    17 add-validator                     // weight = 17, NO stake
  } while drop
} : load-keys-from-file

false =: keys-from-file                  // <-- the switch
keys-from-file
{ "validator-keys" +suffix +".pub" load-keys-from-file }   // branch A: from file
{ VPK'xrQTSOn... 1 add-adnl-validator }                    // branch B: 1 placeholder
cond

3000 =: orig_vset_valid_for              // the appointed set is valid 3000 s
now dup orig_vset_valid_for + 0 config.validators!   // write ConfigParam 34
```

- `add-validator` takes `( pubkey weight -- )` and assigns a **fixed weight of
  17** — there is no balance check.
- The appointed set is short-lived (`orig_vset_valid_for = 3000` seconds): just
  long enough for the `elector` to run the first real election and hand over to a
  staked set.
- By default `keys-from-file = false`, so the checked-in template appoints a
  single hard-coded placeholder validator (`VPK'xrQTSOn...`) — fine for a local
  demo, **not** for a real launch.

## The `validator-keys.pub` format

`load-keys-from-file` reads the file as raw bytes and slices it into 32-byte
chunks (`32 B|`), one per validator. Therefore:

```
validator-keys.pub  =  pubkey_1 ‖ pubkey_2 ‖ … ‖ pubkey_N
                       (each pubkey is exactly 32 bytes, raw Ed25519, no separators)
file size            =  N × 32 bytes
```

The filename includes the zerostate `suffix` (the first CLI arg to
`create-state`): `validator-keys<suffix>.pub`. With no suffix it is just
`validator-keys.pub`.

> **`min_validators = 1`** (ConfigParam 16) in the single-validator bootstrap
> profile. Put exactly the public keys you want in the initial validator set.
> The safer production profile should be restored through governance once
> enough independent validators are ready.

## Step-by-step bootstrap

> `fift` and `create-state` below are build artifacts — they live under
> `build*/crypto/` in a source tree (e.g. `build/crypto/fift`,
> `build/crypto/create-state`) and on `PATH` after an install. Prefix the
> commands with the build path if they are not on your `PATH`.

### 1. Generate validator keys

Use the helper Fift script (committed at `scripts/gen-validator-keys.fif`):

```bash
# from the repo root; produces val-key-1..N (private) + validator-keys.pub
fift -I crypto/fift/lib -s scripts/gen-validator-keys.fif 1
```

This writes:
- `val-key-1` — a raw 32-byte Ed25519 **private** key (the block-signing key
  for that validator). Keep it secret.
- `validator-keys.pub` — 32 bytes (1 × 32), the concatenated **public** keys.

### 2. Assemble `validator-keys.pub`

Two ways, pick by trust model:

- **Mode A — coordinator-generated (simplest; testnets / trusted launch).**
  Run step 1 once with the full count. The coordinator holds every private key
  and hands one to each operator over a secure channel.

- **Mode B — decentralized (recommended for mainnet).** Each operator runs the
  script with count `1` on their **own** machine, keeps their private key, and
  sends only their 32-byte `validator-keys.pub` to the coordinator. The
  coordinator concatenates the submissions in a fixed, agreed order:

  ```bash
  cat op1.pub > validator-keys.pub             # order is consensus-relevant
  test "$(wc -c < validator-keys.pub)" = "32"  # 1 × 32
  ```

### 3. Enable `keys-from-file` in the genesis script

Flip the switch in the native zerostate template you launch from
(`gen-zerostate.fif`):

```diff
-false =: keys-from-file
+true =: keys-from-file
```

Place `validator-keys.pub` in the directory where `create-state` runs.

### 4. Generate the zerostate

```bash
create-state -I crypto/fift/lib -I crypto/smartcont -s gen-zerostate.fif
```

`load-keys-from-file` echoes one `Validator public key = …` line per key, so you
can eyeball the count.

### 5. Verify the appointed set

On a running node, dump ConfigParam 34 (current validator set):

```bash
tos-lite-client -C /data/tos-global.json -v 0 -c "getconfig 34" -c "quit"
```

It must list your N validator descriptors (each with weight 17).

> **Bootstrap invariant:** `validator-keys.pub` must contain `N * 32` bytes and
> injects exactly `N` validators into the zerostate. For the single-validator
> bootstrap profile, `N = 1`.

## Wiring the private keys into validator nodes

Each `val-key-i` is the Ed25519 **block-signing** key whose public half is in
ConfigParam 34. The validator node that signs as validator *i* must hold that
private key in its `validator-engine` keyring. In **Mode B** this is automatic —
the key never left the operator's machine. In **Mode A**, the coordinator must
deliver each private key to its operator, who imports it into the node keyring
(see [Validator.md](Validator.md) and [Validator-Local.md](Validator-Local.md)
for node key/keyring setup). The ADNL address can be bound exactly as the
placeholder branch does with `add-adnl-validator`.

## After genesis: hand over to staked validators

The appointed set is temporary by design. The path to a permissionless,
stake-secured set:

1. The genesis validators produce blocks and keep the chain live.
2. The launch operator **distributes TOS from the main wallet** to anyone who
   wants to validate — at least `min_stake` (10,000 TOS) plus gas each. The
   5 M pre-mine is the reservoir for this (≈ up to 500 candidates at 10 K).
3. Candidates send their stake to the `elector` contract. The first election
   (governed by ConfigParam 15 timing and ConfigParam 17 stake limits) produces
   a **staked** validator set that replaces the appointed one.
4. From then on, validator membership is determined purely by on-chain staking
   elections.

This is the TOS two-phase launch model: pre-mine the initial supply to one
wallet, appoint a bootstrap validator set, then decentralize via stake
distribution and elections.

## Related docs

- [Zerostate.md](Zerostate.md) — genesis construction, TOS pre-mine
- [ConfigParam.md](ConfigParam.md) — ConfigParam 15 (election timing), 16
  (validator counts), 17 (stake limits), 34 (current validator set)
- [Validator.md](Validator.md) / [Validator-Local.md](Validator-Local.md) —
  running a validator, keyring setup
