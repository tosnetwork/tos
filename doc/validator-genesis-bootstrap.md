# Genesis Validator Bootstrap (`validator-pq.pub`)

This document describes how the four original TOS validators are committed to
the production zerostate and how control later passes to ordinary Elector
elections. The monetary parameters are specified in
[`tos-validator-only-token-economics.md`](https://github.com/tosnetwork/doc/blob/main/tos-blockchain/tos-validator-only-token-economics.md).

## Bootstrap invariants

- Genesis contains exactly four original validators in ConfigParam 34.
- The four entries have equal weight and unique ML-DSA-44 consensus keys.
- Every PQ entry includes its validator ID (the staking account) and independent ADNL identity.
- For an Ed25519 ADNL transport key, its ADNL identity is the SHA-256 of
  the serialized `pub.ed25519` TL object (`c6 b4 13 48` plus the transport
  public key). This is not the PQ consensus key ID.
- Original validators are authorized directly by the zerostate and do not
  stake before the first block.
- ConfigParam 16 has a four-validator minimum.
- ConfigParam 17 initially requires a 10,000 TOS individual stake, 40,000 TOS
  aggregate stake, and an effective-stake factor of one.
- The original set is valid for 21,600 seconds (six hours). ConfigParam 15
  uses a 16,384-second election lead and an 8,192-second closing lead, so the
  first election opens at genesis +5,216 seconds, closes at +13,408 seconds,
  and its elected set is due at +21,600 seconds. Elected terms remain 65,536
  seconds and the stake holding period remains 32,768 seconds. The shorter
  election lead also applies to subsequent elections.
- The generator computes this first schedule before producing any state and
  refuses a rotation later than the bootstrap expiry, an empty bidding window,
  or a close at/after rotation. The Elector retains its existing 60-second
  opening-tick tolerance: a tick at least 60 seconds late can still postpone
  the schedule. The production bootstrap rehearsal must verify timely ticks,
  enough accepted stakes and actual rotation before final hashes are frozen.
- There is no hard-coded placeholder-validator fallback in the production
  generator.

The four-key minimum is a liveness floor, not a decentralization target. Four
equal-weight validators require three participating signatures; one unavailable
validator can be tolerated, while two unavailable validators halt progress.

## Why genesis validators do not stake

A new chain cannot complete an on-chain election before it can produce blocks,
and it cannot produce blocks without an authorized validator set. The zerostate
breaks this circular dependency by committing the original validator set in
ConfigParam 34.

This authorization is temporary. The first successful ordinary election
installs a stake-backed set, after which membership continues through the
existing Elector process.

## Protocol and version parameters

| Parameter | Canonical default | Purpose |
| --- | --- | --- |
| ConfigParam 8 version | 16 | Current VM/PQ and shielded-pool execution profile |
| ConfigParam 19 global ID | 1 | Mainnet signature replay domain; local development uses 3 |
| ConfigParam 34 descriptor | `validator_pq_addr#b3` | PQ-only bootstrap consensus identities |
| PQ algorithm ID | 1 (ML-DSA-44) | 1,312-byte consensus public keys |
| ConfigParam 11 proposal voting | ordinary 2/6/2/5, critical 4/7/3/5 (min_tot_rounds/max_tot_rounds/min_wins/max_losses) | A proposal can be voted on for 7 (ordinary) or 8 (critical) rounds, because the registering round counts; it is accepted at 2 / 3 winning rounds and removed after its sixth lost round |
| ConfigParam 12 basechain | `workchain_v2`, `min_split` 0, `max_split` 2, persistent-state split depth 4 | One basechain shard at genesis; load may split it into at most four |
| ConfigParam 30 | Simplex version 2, QUIC enabled, 400 ms target rate, 700 ms first-block timeout, 300 ms minimum block interval; leader windows of 4 slots (masterchain) and 16 slots (shards) | Consensus protocol; distinct from ConfigParam 8 |

ConfigParam 8 is mandatory and critical. Changing a VM version is not
itself enough to change the signing scheme: the validator descriptors and node
keys must also be PQ. ADNL transport identities remain separate from consensus
keys and are not converted to ML-DSA by this configuration.

The canonical template retains its explicitly pinned `SOURCE_DATE_EPOCH` of
1789434000 (2026-09-15 01:00:00 UTC). This is a reproducibility input, **not an
approval to launch a new chain at an expired bootstrap date**. An actual launch
must review and update the epoch and rehearse the initial-set lifetime before
freezing the final hashes. Editing these defaults does not update an existing
chain's ConfigParam 15 or its validator set.

### Schedule template contract

The bootstrap schedule is carried by five named constants in
`crypto/smartcont/gen-zerostate.fif`, each defined exactly once on its own line
as `<seconds> constant <name>`:

| Constant | Canonical value | Used for |
| --- | --- | --- |
| `orig_vset_valid_for` | 21600 | Lifetime of the ConfigParam 34 genesis set |
| `validators_elected_for` | 65536 | ConfigParam 15 `validators_elected_for` |
| `elections_start_before` | 16384 | ConfigParam 15 `elections_start_before` |
| `elections_end_before` | 8192 | ConfigParam 15 `elections_end_before` |
| `stakes_frozen_for` | 32768 | ConfigParam 15 `stakes_frozen_for` |

They are defined before the first-election guards, and ConfigParam 15 and
ConfigParam 34 read them only by name. A tool that derives a different network
profile from this template (for example a testnet ceremony) must replace these
constant lines, not the `config.election_params!` or `config.validators!`
lines, so that the guards check the schedule the derived genesis actually
writes. A profile that the guards refuse produces no zerostate.

## Public-key manifest and operator ceremony

Each operator generates and retains its own consensus seed in a private
directory. Only public output is submitted to the coordinator:

```bash
umask 077
mkdir -m 700 operator-key
build/crypto/pq/tos-pq-consensus-key generate operator-key/consensus.seed
```

The tool prints `algorithm`, `key_id` and the 1,312-byte `public` key in hex;
it does not print the private seed. The validator ID must be the operator's
masterchain staking account: the wallet or nominator pool that will send its
stakes in later elections. The ADNL ID must match the node's configured
transport identity. Neither ID is inferred from the PQ public key. Verify
operator identity and proof of possession before accepting public submissions;
packing a manifest does not prove possession.

The coordinator creates an ordered JSON array of exactly four records:

```json
[
  {"validator_id": "<64 hex characters>",
   "adnl_id": "<64 hex characters>",
   "public_key": "<2624 hex characters>"}
]
```

The example shows one record's shape; four records are required. Pack it with:

```bash
python3 scripts/prepare-pq-genesis-manifest.py operators.json validator-pq.pub
```

The output is public-only and is never overwritten. Each record is validator
ID (32 bytes), ADNL ID (32 bytes), then ML-DSA-44 public key (1,312 bytes), for
**5,504 bytes** total. Order determines validator indices. The production Fift
generator independently checks the exact size and uniqueness of validator,
consensus-key and ADNL identities. It derives the key ID as
`SHA256("TOS-PQ-CONSENSUS-KEY-v1" || 0x0100 || public_key)`; the algorithm field
in this hash uses little-endian encoding as in the native key tool.

The canonical input is `validator-pq<suffix>.pub`. The old 128-byte
`validator-keys.pub` and `scripts/gen-validator-keys.fif` output are classical
test fixtures and are **not** accepted for canonical genesis. The generic test
harness can still construct explicit classical regression fixtures; it defaults
to VM version 16 and refuses PQ fixtures below the supported launch profile.

## Generate and inspect the zerostate

Build the generator and current system artifacts:

```bash
cmake --build build --target create-state gen_fif tos-pq-consensus-key
```

From the ceremony directory containing `validator-pq.pub`, use an absolute
checkout path (set `TOS_REPO` to that path):

```bash
SOURCE_DATE_EPOCH=1789434000 "$TOS_REPO/build/crypto/create-state" \
  -I "$TOS_REPO/crypto/fift/lib" \
  -I "$TOS_REPO/build/crypto/smartcont" \
  -I "$TOS_REPO/crypto/smartcont" \
  -s "$TOS_REPO/crypto/smartcont/gen-zerostate.fif"
```

The generator emits zerostates, their hashes, and bootstrap wallet/configuration
keys. Protect those private files according to the launch ceremony.

Independently decode the generated BOC and verify ConfigParams 8/19/30/34,
the four published identities, algorithm 1, weight 17 each, and exact public-key
hashes. On a running node also inspect Config34 via `tos-lite-client getconfig 34`.
Check ConfigParams 14/15/16/17/28 and balances against the economic specification.
Do not reuse an older zerostate hash after changing these inputs.

## Local three-process fault-tolerance rehearsal

The local network installer, which is maintained outside this repository,
prepares four PQ genesis identities and four independent services. To rehearse
one unavailable validator, stop its own service after setup, for example
`sudo systemctl stop tos-pq-validator@4`.
This is deliberately a one-offline-validator test. It must prove that:

- all three running nodes converge on the same masterchain and workchain
  heads;
- blocks continue to finalize with three of four equal-weight validators;
- ConfigParam 14 creation reaches the Elector fallback collector;
- no validator repeatedly restarts or reports standstill;
- RSS and anonymous memory settle within expected bounded caches; and
- stopping any second validator halts rather than violates safety.

This rehearsal does not replace the four-operator election test.

## First ordinary elections

The production transition is:

```text
four zerostate validators begin producing blocks
  -> the bounded main wallet funds four published controlling wallets
  -> every wallet submits the first 10,000-TOS election stake
  -> every wallet keeps enough principal for the overlapping election
  -> the Elector installs the first ordinary set
  -> a second overlapping elected set is installed
  -> remaining bootstrap-wallet funds are burned
  -> permissionless recurring elections continue
```

Each original validator may receive no more than 20,000 TOS of stake principal
plus the separately measured fee allowance specified by the economic design.
Funding does not make an address a validator: the candidate must submit a valid
bid and be selected by the Elector.

The production rehearsal must exercise the complete path, including failed
submission recovery, configuration installation, stake recovery, and bonus
recovery. Observing only ConfigParam 34 or `funds_created` is insufficient.

## Related documents

- [`tos-validator-only-token-economics.md`](https://github.com/tosnetwork/doc/blob/main/tos-blockchain/tos-validator-only-token-economics.md)
- [`Zerostate.md`](Zerostate.md)
- [`ConfigParam.md`](ConfigParam.md)
- [`Validator.md`](Validator.md)

## Regression verification

The native `create-state` tests generate real zerostate BOCs with public keys
from `tos-pq-consensus-key`, then decode version 16 and the PQ identities. They also reject legacy manifests, duplicate IDs,
wrong timestamps and pre-16 PQ test profiles:

```bash
cmake --build build --target create-state gen_fif tos-pq-consensus-key emulator
uv run pytest -q test/tostester/tests/tostester/test_zerostate_supply.py \
  test/tostester/tests/tostester/test_zerostate_fee_schedule.py \
  test/pq-native/test_z01_genesis_source.py
python3 scripts/check-config-genesis-data-layout.py
python3 scripts/check-pq-launch-cap.py
```

The first-election regression executes the generated Elector's real tick
transaction through `build/emulator/libemulator.so` (`.dylib` on macOS), using
the generated ConfigParams 15 and 34. It checks no election before opening,
then the exact first `elect_at` and `elect_close` at opening and with a 1- or
59-second tick delay. Invalid parameter combinations must fail generation
before emitting either zerostate. This proves scheduling, not successful stake
submission or live validator-set activation.

This generation check does not replace an operational launch rehearsal or
claim that an existing chain was upgraded by editing its genesis template.
