# HTTP bridge pairing

`connect(wallet, { walletSessionPublicKey })` requires the wallet's session
Curve25519 public key before subscribing to a bridge. Obtain it through a
trusted pairing channel, such as a user-verified wallet QR or an authenticated
rendezvous. An SSE `from` field and an unverified wallet-list entry cannot supply
this key. Without this trust anchor, HTTP bridge connection fails closed.
Injected-provider connections keep their existing flow.

The SDK uses a fresh client keypair for each connection. Incoming NaCl boxes
must come from the paired wallet key; the authenticated box binds the account
reply and permissions to that client session. Later connect events cannot
replace an established account. Changing the wallet requires an explicit
`connect()` call with a new trusted key. Low-order keys are rejected.

Only sessions saved under `session_v3` can be restored. Sessions established by
the former unbound first-sender handshake expire instead of inheriting trust.
Restoration checks key encodings, the client keypair and the wallet key.
