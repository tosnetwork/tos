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

## 6f6 read-head follow-up

Counts first: one more demo PASS, one TOSCAN seed FAIL, seven post-send wallet
polls, one matched wallet transaction and one matched registry activation. The
second complete-route command was `uv run python
scripts/verify-e03-localnet-route.py --workdir
test/integration/.e03-localnet-6f6ed9779-20260925`; source
`6f6ed97790ff5579e3026cf869451d7f6650fc71`, exit 1, report SHA-256
`74ff919439c95d577f63cd229cb7d0d439a20789282631fe23c15ed4ab72fe10`.
The report records binary hashes, including validator-engine
`aa0be26e10f758f8d5f314fb57bb503ad2c2bd4f8e7343181d58305e59f54de4`
and tosctl `8e68f5b0cacd00ab8cbf4b1be42c9d59cf6e6865a05aacf8c3d856bae5148727`.

The raw tosctl proxy transcript SHA-256 is
`c5a83d8873de24e92b5f132a790ad227304dbb8fbea6be9367bf4f4ab7168341`.
The registry deploy's `sendBoc` is entry 83 and hashes to
`kIx5sD49hxRJWLetkhehLWSqLq8wmnLHVSwoSJm02Wg=`. Entries 84–90 all
returned seqno 1, balance 50,999,947,869 nanotomis, last LT 69,000,003.
Unlike the 903 run, each response names the exact referenced blocks:

| Polls | Masterchain seqno | Account shard seqno | Wallet seqno |
| --- | ---: | ---: | ---: |
| 84–85 | 57 | 128 | 1 |
| 86–87 | 58 | 130 | 1 |
| 88 | 59 | 133 | 1 |
| 89–90 | 60 | 135 | 1 |

After the failed CLI exited, the saved chain was resumed without rebroadcast.
`toscan/forensic-registry.json` (SHA-256
`e744811edd338d476f2a3bfb5617f799d707510b0899295fb509d0fb51973f63`)
binds that external hash to wallet transaction LT 137,000,001 and its single
outgoing hash to the registry transaction LT 137,000,003. Both transactions
are non-aborted with successful compute; the registry activated. Both are in
the same workchain-0 shard block **136**, root hash
`20EmfSUDiXS7LBDfmMWTmSkuF5V6f+ticFyXN8C5E50=`. The CLI's final poll
referenced shard **135**, one block earlier. Thus its returned seqno 1 was
consistent with the specific block it queried; this run does not support a
client stuck on one cached block.

Historical `getWalletInformation(seqno=N)` on the retained database returns
seqno 1 at masterchain 60/shard 135, and first returns seqno 2 with the matched
LT at masterchain **61**/shard **137**. All seven heights 60–66 and their raw
replies are saved in the forensic file. A second timestamped read of heights
60 and 61 is `toscan/forensic-registry-timed.json` (SHA-256
`b5bd15aaf9a87d52b40b641a63e1c611e1f9c410e44530223bc3318beee85453`):
at wall time 01:35:03.604782 UTC, height 60 still returned seqno 1; at
01:35:03.608063 UTC, historical height 61 returned seqno 2. Those are the
times of the **later diagnostic reads**, not the time height 61 first became
available to the original CLI. The original proxy did not timestamp each poll,
so it cannot establish that wall-clock availability time.

The narrow demonstrated mechanism is a 15-second CLI observation window
ending while the latest referenced shard block was 135 and the transaction was
in block 136, first visible through masterchain reference 61/shard 137. The
next fix needs a bounded, retry-safe *specific-message or deployment-effect*
confirmation rather than another blind send or an unqualified timeout change.
E03 remains OPEN until the same-tree demo and full TOSCAN route both pass.

The follow-up CLI change uses the existing 60-second deployment deadline but
changes the completion condition: it records the wallet cursor before sending,
matches the exact external-message hash in a later wallet transaction, requires
successful wallet compute/action, and requires an outgoing message to the
requested destination. An unrelated seqno increment cannot confirm this
deployment. If the deadline ends without that transaction, the error names its
hash and instructs inspection before retry; the CLI does not resend it. The
unit fixture is the public wallet transaction BOC from this 6f6 run
(`e03_wallet_deploy_tx.b64`, SHA-256
`c0f1c81328e17a50cd40a06f5e74a27bf9e99a996e5e5925286a34427ba803ab`).
The follow-up closes two review boundaries before a new live run: it follows
the transaction predecessor cursor across 10-entry pages until the pre-send
wallet LT, and it retries post-send account/page/BOC read failures inside the
same deadline. Any unconfirmed terminal error retains the exact message hash
and forbids blind resubmission. A matched successful wallet action proves the
payment to the destination was emitted, **not** that the registry/service
contract activated; the TOSCAN seed still checks the target account effect.
This change still needs a new exact-tree full-route run before E03 can close.

Local controls for the pagination/retry follow-up used the retained transaction
BOC: five focused Rust tests passed. Replacing the `Next` page transition with
`Ok(false)` made the >10-transactions test fail at its confirmation assertion;
restoring it passed. Returning from the observation loop on its first read
error made the transient-error test fail at `attempts: 1 != 2`; restoring it
passed. Neither mutation was committed. These are local behavioral controls,
not yet a live-route result.

## e665 exact-tree route

The committed `e6657e008d6a3d6c69dffab478837412ae3333e4` run used
`uv run python scripts/verify-e03-localnet-route.py --workdir
test/integration/.e03-localnet-e6657e008-20260925` and exited 1. Its
`report.json` SHA-256 is
`6c89f6cf10510ec4c83aea145e27b046a5a3ff55b8278fe930547fe61e36643e`;
the tosctl proxy transcript SHA-256 is
`30205153a1789d4387487b214f70e3497d9e937095a3e0d74598528294670189`.
The report records tosctl binary SHA-256
`68e61a57435a67bd73079ac7b91f42a3fde7ffb592bde8936da8d127baae5d26`.
The demo passed. The TOSCAN seed progressed beyond the previous registry
deploy timeout, then failed before its pool-create RPC: Clap parsed the
standalone `-1:` controller address as an option and reported `unexpected
argument '-1'`. This is a CLI invocation error, **not** an Elector or pool
rejection. The raw seed output and all 124 tosctl proxy responses are retained.
The next tree passes the negative-workchain address as a single
`--controller=-1:...` argument; a focused test checks the exact tokenization.
Restoring the old two-token form made that test fail at the named token
assertion; the one-token form and the full seven-test localnet-route unit suite
passed after restoration.
This run is not a full TOSCAN PASS and E03 remains OPEN.
