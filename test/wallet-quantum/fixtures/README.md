# Public genesis account fixture

`public-genesis-accounts.json` contains SDK-generated public code, StateInit and
data cells retained from the native cached-recovery test. Its provenance records
the source revision and original fixture digest. No private key or seed is
included; the underlying deterministic test keys must never protect funds.

The isolated candidate runner creates the wallet/module/vault directly in the
basechain genesis. It deducts their aggregate allocation from the masterchain
faucet and checks the original 5-billion-TOS total supply. Genesis account
creation proves neither a deployment transaction nor creation/restore custody.

The live verifier must prove all three active accounts at one authenticated
masterchain checkpoint, with exact SDK address/code/data identities. Ordinary
RPC output is not that evidence. Frozen fixture code is a test identity, not
final release-code acceptance. Mobile custody, signed deployment, POP, migration,
fee state, finality and recipient delivery remain separate gates.

## Self-pay fixture

`public-self-pay-accounts.json` is a separate self-pay v1 fixture. It uses the
isolated candidate's global ID 1 and 32-byte `0x42` namespace, with public keys
from the deterministic self-pay vectors. It contains no secret keys or seeds.
These identities must never hold real funds.

The three distinct wallet IDs cover an active account, a funded uninitialized
account, and an absent address. `create-state` modes 2, 1 and 0 respectively
establish those states; mode 0 computes an address without inserting an account.
Each record retains its original StateInit and QSI1 identity, including for the
uninitialized and absent accounts. The generator recompiles the current FunC
source and checks its code hash and all regenerated identities against the
frozen input before constructing the genesis allocation.

After building the full native node and proof verifier and generating Python
TL bindings (`uv run test/tostester/generate_tl.py`), run:

```sh
uv run python scripts/test_quantum_self_pay_fixture.py
uv run python scripts/capture-quantum-self-pay.py --build-dir build \
  --input test/wallet-quantum/fixtures/public-self-pay-accounts.json \
  --out build/quantum-self-pay-capture
```

The output directory must be new. The runner owns and stops its disposable
node process group, including surviving children after a leader crash. It
starts no wallet client and waits until the masterchain references nonzero
basechain blocks before requesting account proofs. The JSON-RPC readiness
check is only a startup hint; it does not authenticate any state. The native
verifier verifies configuration and all three accounts at one
authenticated masterchain checkpoint, then replays the genuine account proof
and requires a wrong anchor and missing account material to be refused for
their specific reasons. `readiness.json` and `network-exit.json` retain the
startup observation and the reaped leader's exit status.
`mobile-fixture/` contains only public JSON and raw TL proof material for
mobile re-verification at its recorded controlled time. `network/` contains
private node runtime data and must not be copied into fixtures or artifacts.

Genesis allocation and authenticated state reads do not prove a deployment
transaction, key custody, signed payment, rescue/migration, or current-live
mobile acceptance. The separate three-account capture does not replace the
historical module/vault fixtures or claim their protocol remains the default.
