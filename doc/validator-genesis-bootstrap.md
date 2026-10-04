# Genesis Validator Bootstrap (`validator-pq.pub`)

This document describes how the four original TOS validators are committed to
the production zerostate and how control later passes to ordinary Elector
elections. The monetary parameters are specified in
[`tos-validator-only-token-economics.md`](https://github.com/tosnetwork/doc/blob/main/tos-blockchain/tos-validator-only-token-economics.md).

## Bootstrap invariants

- Genesis contains exactly four original validators in ConfigParam 34.
- The four entries have equal weight and unique ML-DSA-44 consensus keys.
- Every PQ entry includes its stable controller ID and independent ADNL identity.
- For an Ed25519 ADNL transport key, its ADNL identity is the SHA-256 of
  the serialized `pub.ed25519` TL object (`c6 b4 13 48` plus the transport
  public key). This is not the PQ consensus key ID.
- Original validators are authorized directly by the zerostate and do not
  stake before the first block.
- ConfigParam 16 has a four-validator minimum.
- ConfigParam 17 initially requires a 10,000 TOS individual stake, 40,000 TOS
  aggregate stake, and an effective-stake factor of one.
- The original set is valid for 131,072 seconds. This value covers two complete
  65,536-second election intervals, but it must still pass the production
  bootstrap rehearsal before the final zerostate hashes are frozen.
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
| ConfigParam 30 | Simplex version 2, QUIC enabled | Consensus protocol; distinct from ConfigParam 8 |
| ConfigParam 47 | Compiled controller v1 code hash | Admission for subsequent controller-based elections |

ConfigParams 8 and 47 are mandatory and critical. Changing a VM version is not
itself enough to change the signing scheme: the validator descriptors and node
keys must also be PQ. ADNL transport identities remain separate from consensus
keys and are not converted to ML-DSA by this configuration.

The canonical template retains its explicitly pinned `SOURCE_DATE_EPOCH` of
1789434000 (2026-09-15 01:00:00 UTC). This is a reproducibility input, **not an
approval to launch a new chain at an expired bootstrap date**. An actual launch
must review and update the epoch and rehearse the initial-set lifetime before
freezing the final hashes. This change does not alter supply, reward, stake,
bootstrap lifetime or fee parameters.

## Public-key manifest and operator ceremony

Each operator generates and retains its own consensus seed in a private
directory. Only public output is submitted to the coordinator:

```bash
umask 077
mkdir -m 700 operator-key
build/crypto/pq/tos-pq-consensus-key generate operator-key/consensus.seed
```

The tool prints `algorithm`, `key_id` and the 1,312-byte `public` key in hex;
it does not print the private seed. The controller account ID must be the
operator's intended stable masterchain validator identity, derived from the
controller StateInit with its separate root authority. The ADNL ID must match
the node's configured transport identity. Neither ID is inferred from the PQ
public key. Verify operator identity and proof of possession before accepting
public submissions; packing a manifest does not prove possession or deploy a
controller.

The coordinator creates an ordered JSON array of exactly four records:

```json
[
  {"controller_id": "<64 hex characters>",
   "adnl_id": "<64 hex characters>",
   "public_key": "<2624 hex characters>"}
]
```

The example shows one record's shape; four records are required. Pack it with:

```bash
python3 scripts/prepare-pq-genesis-manifest.py operators.json validator-pq.pub
```

The output is public-only and is never overwritten. Each record is controller
ID (32 bytes), ADNL ID (32 bytes), then ML-DSA-44 public key (1,312 bytes), for
**5,504 bytes** total. Order determines validator indices. The production Fift
generator independently checks the exact size and uniqueness of controller,
consensus-key and ADNL identities. It derives the key ID as
`SHA256("TOS-PQ-CONSENSUS-KEY-v1" || 0x0100 || public_key)`; the algorithm field
in this hash uses little-endian encoding as in the native key tool.

The canonical input is `validator-pq<suffix>.pub`. The old 128-byte
`validator-keys.pub` and `scripts/gen-validator-keys.fif` output are classical
test fixtures and are **not** accepted for canonical genesis. The generic test
harness can still construct explicit classical regression fixtures; it defaults
to VM version 16 and refuses PQ fixtures below the supported launch profile.

## Generate and inspect the zerostate

Build the generator and current system/controller artifacts:

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
keys. Protect those private files according to the launch ceremony. The generated
ConfigParam 47 admits the exact controller artifact compiled from this checkout;
it does not initialize any controller's operating authorization or deploy its
account. See [controller funding](Local-PQ-Network.md#controller-funding-before-election-rehearsal).

Independently decode the generated BOC and verify ConfigParams 8/19/30/34/47,
the four published identities, algorithm 1, weight 17 each, and exact public-key
hashes. On a running node also inspect Config34 via `tos-lite-client getconfig 34`.
Check ConfigParams 14/15/16/17/28 and balances against the economic specification.
Do not reuse an older zerostate hash after changing these inputs.

## Local three-process fault-tolerance rehearsal

The local installer now prepares four PQ genesis identities and four independent
services. To rehearse one unavailable validator, stop its own service after setup:

```bash
sudo ./scripts/setup-testnet.sh --clean
sudo systemctl stop tos-pq-validator@4
```

See [Local PQ network](Local-PQ-Network.md) for the local development profile.
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
from `tos-pq-consensus-key`, then decode version 16, PQ identities and the exact
controller admission hash. They also reject legacy manifests, duplicate IDs,
wrong timestamps and pre-16 PQ test profiles:

```bash
uv run pytest -q test/tostester/tests/tostester/test_zerostate_supply.py \
  test/tostester/tests/tostester/test_zerostate_fee_schedule.py \
  test/pq-native/test_z01_genesis_source.py
python3 scripts/check-config-genesis-data-layout.py
python3 scripts/check-pq-launch-cap.py
```

Sensitivity was checked by changing the canonical version back to 14: the
real-BOC positive test failed at `14 == 18`, and passed after restoring 18.
This generation check does not replace an operational launch rehearsal or
claim that an existing chain was upgraded by editing its genesis template.
