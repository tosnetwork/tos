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

The first product proof was `ca842b0f1`, recorded in
`T3-CONFIG-WALLET-FIRST-STAKE-DIAGNOSTIC.md`. T05 independently repeated it on
the exact retirement tree `d74c3abd3e694fcfdbd2bc5c2099282b82e1e396`:
`test/integration/.pq-tosctl-config-wallet-product/20260924T080636Z/report.json`,
SHA-256 `6b9141ce9bcc3b55850f729697e0e5541791e71a490e53105bbac4d330cb0937`,
`passed=true`, `failures=[]`. The product CLI exited 0. Complete pool (2
transactions, 1 page) and controller (1 transaction, 1 page) histories bind
query `1790237617` to the pool's Elector `STAKE_ACCEPTED`, reason 0. Live
ConfigParam 34 at `utime_since=1790237797` pairs controller
`dae8de3bc465a977f3c2c40efa33f89d463b46a1c9498e17a19a0603101c57d8`
with actual relay ADNL
`c513062a689a3af0a85d70a08e6573ec095ead28e650e85782fa6d1f08f3a19c`.
Raw pool/controller JSON SHA-256 values are
`33fb76efd0b7968f03b2cad618ef0a19480a88b39cf4d92b8979b41c31eeedd6`
and `cfe976b56b5f15a2eb4f81a3c8d9708274b1b314aef3d166a323a97803ef4d38`;
the raw live Config34 text is
`8d754fcff431a5603702f3bb85dca30b2c051c5f4b2d536dd3b7a932de08708f`.
This is a single co-located product proof, not release-scale evidence.
The new sandbox negative constructs the retired classical body, requires the
compiled PQ pool transaction to abort, and requires no controller relay.

T05 removes only the supported operator's classical Fift entry. The C++
legacy fixture, liquid-staking product exclusion, and base Fift tools retain
their separate T06–T12 disposition; T3 as a whole remains OPEN.
