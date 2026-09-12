# Genesis Validator Bootstrap (`validator-keys.pub`)

This document describes how the four original TOS validators are committed to
the production zerostate and how control later passes to ordinary Elector
elections. The monetary parameters are specified in
[`tos-validator-only-token-economics.md`](tos-validator-only-token-economics.md).

## Bootstrap invariants

- Genesis contains exactly four original validators in ConfigParam 34.
- The four entries have equal weight and unique Ed25519 signing keys.
- Every entry includes its ADNL identity.
- The ADNL identity is the SHA-256 hash of the serialized `pub.ed25519` TL
  object: the four-byte prefix `c6 b4 13 48` followed by the 32-byte public key.
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

## Public-key manifest

The production generator reads `validator-keys<suffix>.pub` from the current
working directory. With no suffix, the filename is `validator-keys.pub`.

The file is a raw concatenation with no headers, lengths, or separators:

```text
validator-keys.pub =
    public_key_0 || public_key_1 || public_key_2 || public_key_3

public-key size = 32 bytes
manifest size   = 4 * 32 = 128 bytes
```

Order is consensus-relevant because it determines validator indices. The
generator aborts unless the file is exactly 128 bytes and all four public keys
are unique.

For every key, `gen-zerostate.fif` derives the corresponding ADNL identity and
uses `add-adnl-validator` with equal weight 17. Operators must configure their
validator-engine instances with the matching signing and ADNL private key.

## Key-generation ceremony

Each operator should generate its key on its own secured machine and disclose
only the raw 32-byte public key. The launch coordinator must not collect
production private keys.

The helper defaults to four keys for isolated test ceremonies:

```bash
build/crypto/fift -I crypto/fift/lib \
  -s scripts/gen-validator-keys.fif 4
```

It writes `val-key-1` through `val-key-4` and the concatenated
`validator-keys.pub`. Coordinator-generated private keys are acceptable only
for disposable local networks.

For a production ceremony, each operator instead generates one key and submits
the 32-byte public part. The coordinator verifies identity and proof of
possession, then concatenates the four submissions in the published order:

```bash
cat operator-0.pub operator-1.pub operator-2.pub operator-3.pub \
  > validator-keys.pub
test "$(wc -c < validator-keys.pub)" = "128"
```

Before generation, publish a signed manifest containing:

- index;
- raw public key;
- derived ADNL identity;
- controlling masterchain wallet;
- operator and control disclosure; and
- a hash of the complete ordered 128-byte manifest.

## Generate and inspect the zerostate

Run the canonical production generator from the directory containing the key
manifest:

```bash
build/crypto/create-state \
  -I crypto/fift/lib \
  -I crypto/smartcont \
  -s "$PWD/crypto/smartcont/gen-zerostate.fif"
```

The generator emits `zerostate.boc`, the basechain zerostate, their hashes, the
main-wallet key, and the configuration-contract key. Production key custody
must follow the launch ceremony rather than leaving generated private keys in
an ordinary working directory.

Inspect the initial validator set on a running node:

```bash
tos-lite-client -C /data/tos-global.json -v 0 \
  -c "last" \
  -c "getconfig 34" \
  -c "quit"
```

ConfigParam 34 must show:

- `total=4` and `main=4`;
- four `validator_addr` descriptors;
- weight 17 for every descriptor;
- the four published signing keys; and
- the four independently derived ADNL identities.

Also verify ConfigParams 14, 15, 16, 17, and 28 against the economic
specification, and independently parse the zerostate to confirm its native
balances.

## Local three-process fault-tolerance rehearsal

The local test infrastructure can commit four genesis identities while running
only three validator processes:

```bash
sudo env \
  VALIDATORS=3 \
  GENESIS_VALIDATORS=4 \
  VALIDATOR_ECONOMICS_PROFILE=1 \
  ./scripts/setup-testnet.sh --clean

./scripts/testnet-ctl.sh start
```

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

- [`tos-validator-only-token-economics.md`](tos-validator-only-token-economics.md)
- [`Zerostate.md`](Zerostate.md)
- [`ConfigParam.md`](ConfigParam.md)
- [`Validator.md`](Validator.md)
- [`Validator-Local.md`](Validator-Local.md)
