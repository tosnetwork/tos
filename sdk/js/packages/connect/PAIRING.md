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

## Refusals

`connect()` throws, and does not open a bridge subscription, when an HTTP-bridge
wallet is given:

- no `walletSessionPublicKey`;
- a key that is not exactly 64 hex characters;
- a low-order (unsafe) Curve25519 key.

## React

`@tos/connect-react` forwards the key: call
`connect(wallet, { walletSessionPublicKey, items })` from `useConnect()`. A
refused connection is reported through `connectError` (and a console warning)
rather than swallowed.

## Current limitation

The bundled mobile wallets do not yet offer an out-of-band pairing step, so a
dApp cannot obtain their session key in advance. Until they do, HTTP-bridge
connections to them are refused; injected wallets are unaffected.
