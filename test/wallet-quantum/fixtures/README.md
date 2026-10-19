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
