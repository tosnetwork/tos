# E03: fixed-tree JSON-RPC/TOSCAN diagnostic (2026-09-25)

Counts first: the demo passed; the complete TOSCAN route failed; one captured
`sendBoc` was matched to one successful wallet transaction and one successful
destination deployment. E03 remains **OPEN**. This is not a TOSCAN PASS or a
complete explorer-to-node HTTP trace.

The exact network source was `9031357b81ce011a09d64686304bea79c6763497`.
Command: `uv run python scripts/verify-e03-localnet-route.py --workdir
test/integration/.e03-localnet-9031357b8-20260925`; exit 1. The report is
`test/integration/.e03-localnet-9031357b8-20260925/report.json` (SHA-256
`c06ee37306b4c404a1f5a240231135a02fae740698aad08ae2b5006f09bd0eed`).
Its binary hashes are recorded in the report: validator-engine
`82b35395d2a2cfd4385730f2dfac195351e00f3b790dde6acdf287cfef34c707`,
dht-server `934392cdff095831e4eaad8d0e29494787989eb5b7f34e7f89d9641373220c39`,
lite-client `c939b698235f9d846a3a4d7923fcc177c0bef874099a3597cf45ef45e13357e1`,
tosctl `8e68f5b0cacd00ab8cbf4b1be42c9d59cf6e6865a05aacf8c3d856bae5148727`.

The demo's before/after balance was 0/4,999,999,000 nanotomis, its external
`getMasterchainInfo` and `getAddressInformation` replies were retained, and its
bounded interrupt exited 0. TOSCAN's explorer became ready, then the seed's
`agent registry deploy --name nova-capabilities` failed with
`Transaction timeout expired`. The original CLI output is
`toscan/toscan.stdout.log` (SHA-256
`bdf292246ac40613feffaaea4de058ade4d9ddcfc6f59138c4f0901cce3d1ecf`).

The proxy's 90 raw tosctl exchanges are in `toscan/tosctl-http-transcript.jsonl`
(SHA-256 `32d4fe0f8909681689e4956eed40bdbe62113a6da837ddacee3d7d92e0ce1885`).
For request ID `f0acd07a-83fa-425c-9395-49993736c866`, the captured BOC has
external-message hash `jODOTlVsLagu+UTdyUtzF8ZUKgb4dCoTnuQiM7T1uoI=`;
`sendBoc` returned HTTP 200/`status:1`. All seven subsequent captured
`getWalletInformation` replies for the payer reported seqno 1, balance
50,999,947,869 nanotomis and unchanged transaction LT 66,000,003.

The saved database was then resumed without resending the message. The
read-only forensic capture is `toscan/forensic-registry.json` (SHA-256
`918246a4d022d649897e340bd12768394d036ce9a9ffa9a15c7eed0be8d16204`).
The payer now reported seqno 2 and balance 49,799,762,709 nanotomis. Its
transaction LT 134,000,001 at chain time 1790298431 (01:07:11 UTC) had the
*same external inbound hash*, `aborted=false`, compute success/exit 0 and
action success/result 0. Its sole 1.2 TOS outgoing message hash was
`NV5VQhq7NW4h8JN4EWOaaethobmWdqIs6xFUqq7tUfw=`. The registry account's
transaction LT 134,000,003 at the same chain time had that exact inbound
hash, activated the account and also completed without abort. This proves
the message **eventually executed**, not merely that the server accepted a
broadcast. The 01:07:11 `utime` is a chain timestamp; it does not prove the
transaction was readable from this JSON-RPC server's selected head before the
CLI failed at about 01:07:24. The seven poll responses report neither the
masterchain nor shard block they referenced, and the proxy did not timestamp
each exchange. The failure could therefore be a lagging referenced block or
another observation/cache issue; the evidence does not choose between them.

The production CLI waits 15 seconds for `getWalletInformation.seqno` to differ
from its initial value (`nodectl/utils.rs:29,239`), then returns failure before
the deploy command writes its local registry record. A simple timeout increase
would not establish whether a failed command executed and would leave retry
semantics ambiguous. The next correction must confirm the *specific* sent
message or deterministic deployment effect before recording success, and make
timeout recovery safe against a second fee-bearing send. Until that is tested,
the complete E03 route remains OPEN.

Separately, the Config34 JSON/BOC gate was tightened to require contiguous
indices, both members of a two-entry control, weights/cumulative weights,
ML-DSA-44 public-key length and key-ID derivation, unique identities/ADNL, and
one-to-one agreement with the independently provisioned genesis node. The
earlier one-member JSON/BOC result alone was insufficient to sign off TOSCAN.
At committed source `98373ef5f`, a separate one-validator localnet captured
`test/integration/.e03-config34-98373ef5f-20260925/config34-raw.json`
(SHA-256 `153518692c477716bf715afedaac408d63c02f09506ed4b915959f812fde7791`)
and the verified result (SHA-256
`5c567497a25c04e6ed8ac807fa0c088eb82aa772f92f6e97171f73e9be89dd6e`).
The live response has index 0, cumulative weight 0, weight 17, algorithm 1,
`public_key:null`; BOC hash
`ed5d1f900702c9e99518f4e3ee6e3b6029c53bf80a658af0a1daf36bdd53de77`
matched the JSON and the separately provisioned node identity/ADNL/key tool.
The validator-engine binary SHA-256 was
`d862c6ad1dacd40e5214a05aaf4990947515eb015f3820294e2eead13cb9ca87`.
This is a direct Config34 check, **not** a TOSCAN seed or explorer PASS.
