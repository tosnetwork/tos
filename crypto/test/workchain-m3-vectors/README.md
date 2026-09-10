# M3 transfer test vectors

**Synthetic test data only, not real chain data.** Wallet keys, balances and
pending amounts are known constants in `uno/prover/examples/m3-vectors.rs`.
The public wallet `prove()` uses fresh OS randomness. Two SEND inputs share one
semantic statement/pre-state/operationID, but have different valid authorization.

| Directory | Old source available | Transfer/selected values | Public fee | New source available |
|---|---:|---|---:|---:|
| send | 50000 | 137 | 11 | 49852 |
| collect1 | 3107 | 137 | 17 | 3227 |
| collect3 | 3107 | 137, 251, 89 | 17 | 3567 |

Bob initially has four pending receipts (137, 251, 89, 433); COLLECT leaves
unselected receipts. SEND appends a pending receipt, not a direct available
balance credit. These are test tariff values and profile identities, not
production configuration defaults. The kernel uses its fixed Pedersen generators;
no generator point can be supplied by the candidate.

Each directory contains:

- `prestate.boc`: `HashmapE 256 ^UnoV2AccountState`, keyed by account address.
  Pin its representation hash from `environment.txt` as the trusted fixture
  root, then read Alice/Bob through that dictionary. This is an authenticated-root
  unit-test input, not an inclusion proof against a real network.
- `alice.boc` / `bob.boc`: corresponding full formal account records, including
  full pending origins/ciphertexts. Packing checks equality with dictionary entries.
- `environment.txt`: every explicit `WorkchainTransferEnvironment` input.
  `current_height` maps to `height`; other names match fields or their nested
  limits/protocol/rules/profiles records. All hex words are 32 bytes except
  `domain` (80 bytes). No field is a candidate-supplied authority.
- `candidate-1.boc`, plus `send/candidate-2.boc`: formal `UnoV2TransferInputV1`.
- `request.txt`: independently assembled test public statement for comparison;
  the host must reconstruct its own values, not trust this as its verdict/input.
- `candidate-N.verify.txt`: the public statement plus authorization read back
  from the actual candidate BOC. `candidate-N.verified.txt` records the same
  authorization accepted through the exported `uno_crypto_verify_v2` ABI.
- `public.txt`, `semantic.boc`, `authorization.txt`, `expected.txt`: generator
  intermediates and test expectations. `authorization.txt` is the latest proof
  in the directory, so the SEND pair is retained in its two named candidates.

Receipt origins use the configured network, source full address, SEND kind and
source nonce; the sole output index is zero. Selected IDs are ordered by the
wallet generator; the shared codec preserves that order. The UMS1 old-statement
hash uses the shared `workchain-transfer-statement.h`, not a second implementation.

Regenerate with an existing native CMake build of this source tree:

```sh
python3 test/uno-m3-vectors.py --build /absolute/native-build \
  --output crypto/test/workchain-m3-vectors
```

The script rebuilds the exact C++ packing tool, builds the locked/offline wallet
example, generates four fresh proofs, packs their candidates, and verifies the
persisted authorization through the real ABI. A changed context must be rejected.
`NODE_LINK=ON` is not required by this generator: ABI calls execute inside its
Rust utility, not a node. Host execution and nonce-consumption tests belong to
the host consumer; proof acceptance alone is not execution or devnet evidence.
