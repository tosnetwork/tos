# T3: tosctl election daemon first PQ pool stake

This closes the **election daemon caller's first-stake path**, not the other
classical Fift callers, a scale claim, or the Mac portability integration.
The run used one co-located accelerated PQ chain, the product `tosctl service`
election runner, the product wallet, a single-nominator pool, an admitted
controller, and the controller's original deployment StateInit imported from
its on-chain transaction. The fixture provisioned accounts and capital; it
did not sign or submit the primary stake.

## Exact-tree result

| Field | Evidence |
| --- | --- |
| Source commit | `92f79ddf31436e6ce8aacee1382a59328063bbf7` |
| Report | `test/integration/.pq-tosctl-election-daemon-product/20260924T072620Z/report.json` |
| Report SHA256 | `f0ffb55470730ee3d78717bfcce91789490b9b89e943581ea5021edb5b61ba50` |
| Outcome | `passed=true`, `failures=[]` |
| tosctl binary SHA256 | `8e68f5b0cacd00ab8cbf4b1be42c9d59cf6e6865a05aacf8c3d856bae5148727` |
| validator-engine binary SHA256 | `556005c3324e7af4db048a966921057b5ba93c79d0fd7c571761639f05016b5c` |
| Daemon log SHA256 | `9d1bea37c9762844eff25747185d91125c44110573c98c1837f6ed99d89ba0ed` |

The daemon log contains `node [validator-1] send stake`. The bounded pool
transaction scan covers one page and is complete: it identifies the product
wallet's `NEW_STAKE` order with query ID `1790235203` and the exact Elector
reply `0xf374484c` (`STAKE_ACCEPTED`), reason `0`. The controller scan is also
complete (one page). Raw histories are preserved as
`product-stake-{pool,controller}-transactions.json`, SHA256 respectively
`a6ac07eacb53e1c02acefe260f2107abb0c794bf18dca90f887154bfc2b2e4aa`
and `788c5039054687fb711b03ae26d982492275528151e3804856bcc40d8f025b92`.

The controller relay for that query carried ADNL
`7d8c31130c5a51dd973de396a6ff61ae103ba9248254259fac9f8dd5dbbb06e1`.
The live ConfigParam 34 has `utime_since=1790235382` and pairs that ADNL with
controller ID
`dae8de3bc465a977f3c2c40efa33f89d463b46a1c9498e17a19a0603101c57d8`.
Its raw `live-config34.txt` has SHA256
`503f96852dd4cbf2eb439d7256d71424225a77f3a01470f40fe22e2591145bf4`;
the two values are present together in that text. The post-order
`participant_list_extended` observation succeeded on its first attempt;
its raw HTTP/JSON envelope has SHA256
`fff962bc2e7392d62a4362ee38615aad173b1e4c588510889d004ca5c2178734`.

## Red boundaries and repair

At `f8f15618c`, the daemon sent lite-server `GetConfigParams[34]` and
`GetShardAccountState` constructors to the validator control socket. That
socket rejected both with `Unknown constructor` (`0x231f41e2` and
`0x34adc00a`), so no wallet-to-pool order was sent within 150 seconds. Report
SHA256: `a3c8932d888d8016b93a8029e86f9e647bbe8edd074439eaad8c9e1fde57bc45`;
daemon log SHA256:
`f30ab20e3ea32409feb899b1c62e6313d63767f66349acb24d5178c4335a1116`.
This was a pre-order protocol-route failure, not an Elector refusal.

`272eebe28` moved account balances and ConfigParam 34/36 reads to chain RPC,
using the exact raw ConfigParam 34 value cell for the pool maintenance hash.
That run reached the daemon's wallet-to-pool order, but the observer stopped
the service immediately, then a `runGetMethodStd` diagnostic call failed
before it saved Elector feedback. Report SHA256:
`475c7670f451d671a1abb37bb4cc44f68dde0b1007c89cca6eed35415c7c180f`;
daemon log SHA256:
`c3fc0354ab4d799e1fb6390e78864d96bb81ddbfc363002254838a96707a45be`.
That run proves only that the daemon sent the order; neither acceptance nor
rejection was measured.

`92f79ddf3` keeps the daemon alive until the exact pool feedback window ends,
persists raw JSON-RPC diagnostic envelopes (including errors), and does not
let a failed optional participant-list observation suppress the transaction
scan. The service is stopped before fixture support-pool stakes. A sent order
alone cannot pass the run: exact Elector acceptance and the live Config34
controller/relay-ADNL pair are both required.

The protocol repair's local gates were 25 chain-RPC and 43 elections unit
tests, 36/36 configure-only source guards, and a required 36-name guard
inventory. A control-socket account-read mutation and a reintroduced
control-socket config read both made the routing guard red; replacing the raw
parameter cell with an empty cell made the hash-preservation test red.

This evidence closes only the daemon first-stake caller. The Fift inventory's
remaining callers, product-scale operation, and separate portability review
retain their own closure conditions.
