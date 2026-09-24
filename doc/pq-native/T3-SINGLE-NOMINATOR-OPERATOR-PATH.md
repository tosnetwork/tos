# T05: single-nominator pool operator path

The supported operator path is `tosctl config wallet stake`, not the former
`crypto/smartcont/single-nominator-pool/validator-elect-signed.fif`. The latter
produced a classical Ed25519 body rejected by the PQ pool. Its unchanged byte
codec is retained only under `crypto/test/fift/fixtures/` for historical
`test-smartcont.cpp` parity; it is not a product entry point or PQ test.

After deploying a single-nominator pool and its admitted Validator Controller,
bind the operator wallet and pool to the validator node. Retain the controller's
deployment transaction BOC; its original StateInit cannot be recovered from
mutable account data. Import that public artifact into the idle node binding:

```text
tosctl config --config CONFIG bind add --node NODE --wallet WALLET --pool POOL
tosctl config --config CONFIG bind import-birth --node NODE \
  --transaction-boc DEPLOYMENT_TRANSACTION.boc \
  --output /absolute/path/controller-birth.boc
tosctl config --config CONFIG wallet stake --binding NODE --amount STAKE_TOS
```

The final command asks the node for `createPqStakeAuthorization`, checks the
live pool roles and ConfigParam 47 admitted controller code, and uses the
production `nominator::new_stake_with_witness` path. Missing or mismatched
birth artifacts refuse before wallet send. The import validates transaction
shape and identity offline; it is not an independent chain-finality proof.

The exact-tree `ca842b0f1` product run is the live first-stake evidence:
`test/integration/.pq-tosctl-config-wallet-product/20260924T063630Z/report.json`,
SHA-256 `b5a448040fd75f5f55e206751f86831cf68b3c2de5d3f84fdca236e2447a693d`,
as recorded in `T3-CONFIG-WALLET-FIRST-STAKE-DIAGNOSTIC.md`. It records product
CLI exit 0, pool Elector `STAKE_ACCEPTED` for query `1790232216`, and live
ConfigParam 34 pairing the configured controller with its actual relay ADNL.
The new sandbox negative constructs the retired classical body, requires the
compiled PQ pool transaction to abort, and requires no controller relay.

T05 removes only the supported operator's classical Fift entry. The C++
legacy fixture, liquid-staking product exclusion, and base Fift tools retain
their separate T06–T12 disposition; T3 as a whole remains OPEN.
