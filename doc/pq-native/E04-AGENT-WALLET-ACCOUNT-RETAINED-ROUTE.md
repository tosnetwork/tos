# E04 Agent Wallet / Agent Account retained route: custody boundary

Status: OPEN. The full advertised route has not completed on the current PQ tree. This is an E04 fixture/product-workflow finding, not a consensus failure.

## Exact runs and observed stop

The third, three-view run used committed `a778652c7` and exited 1 after 18
checks. Its full console is
`test/integration/.e04-agent-wallet-a778652c7-20260925-console.typescript`
(SHA-256 `b22947ef98857cf1d29fd5aff925f0d0b4de802bc98fccb5357f1024f19ffe00`).
The positive account completed exact-Gift winner resolution by three distinct
RPC views and task-send; a separate cancellation account exercised its negative
control. The next command, `agent account update-policy --wallet agent-1
--amount 0.05 --yes`, printed query ID `7689306359782703105` and failed at the
wallet's 15-second seqno poll. The later policy-effect wait was never reached.
This is not an E04 PASS.

Read-only forensics on a **copy** of that run's retained node DB bind this
query ID to the wallet's outgoing message by decoding the transaction BOC:
opcode `0x41475001`, query ID `7689306359782703105`, outgoing hash
`5Ra5HKXrRwbbmM7/ImED0zLD8VO99F3eHRJvfyGQdmg=`. The wallet transaction
is `lt=182000001` in shard block 181, with compute exit 0 and successful action.
The Agent Account's `lt=182000003` inbound hash is the same; its compute exit 0
and action also succeeded. A subsequent chain read gives account seqno 2 and
the requested policy, `max_per_tx=1000000000` and `daily_limit=5000000000`
nanotos. The raw RPC exchanges and transaction BOCs are in
`test/integration/.e04-agent-wallet-a778652c7-forensic/capture-policy/raw.json`
(SHA-256 `72fbd9cf62bc8a15d51a043a16665717902352cbf80b99b5aca3c9a4449238ed`);
the decoded summary is `summary.json` in the same directory (SHA-256
`6f18ecd68f49700a1e2fece5309434db0c3a7da7b8b0e18f75a8ded6bf90617a`).
`scripts/e04_policy_forensic.py` reproduces the read-only query-ID/hash join.
This proves eventual execution and policy effect, **not** that the transaction
was visible to the CLI before its 15-second deadline. The run has no retained
per-poll RPC transcript capable of making that timing distinction. The exact
message must not be resent on the ambiguous timeout. The shared owner-action
confirmation should use the exact submitted wallet message and then verify the
Agent Account effect, rather than treating a short seqno wait as failure.

Commit `55c8b5bea` applies that shared owner-action route change. Its source
ordering test and the six exact-confirmation tests pass (7/7); restoring the
single-send/short-seqno-poll structure makes the new routing test fail. This
is a local gate, **not** a successful E04 runtime rerun.

The subsequent retained-route negative controls now use a separate cancellation
target and require the cancellation's exact signed BOC to be the sole successful
post-baseline Agent Account inbound; no unrelated seqno can pass. Both 60-second
absence windows fail on any RPC read error, retain start/end finalized block IDs
for all three independent nodes, and require progression. The expiry control
reads `gen_utime` from the header of an exact finalized masterchain block and
requires it to exceed `valid_until` before broadcasting. The process map records
each node PID, RPC port and DB directory. Five short tests pass, including a
later-RPC-error mutation that makes the old permissive window fail the test.
The clean and mutant raw logs are in
`test/integration/.e04-agent-wallet-negative-controls-20260925/` with SHA-256
`4b9317cbdc17d473ea845a793b568d3ad01a1562c618caa11926795941535830`
and `e69016396a2008c866051583a6d8e34d3cf654e0e2cda55c01743f2851e9c471`.
These controls are not yet real-chain E04 evidence; the fixed-tree full run is
still required before this entry can close.

The first full run from committed `c951856a6` exited 1 earlier, at `agent
wallet fund --name agent-1 --from funder --amount 2 --yes`; it never reached
Gift or update-policy. Its complete console is
`test/integration/.e04-agent-wallet-c951856a6-20260925-console.typescript`
(SHA-256 `c9e95c3cc07b5e7af2d10b20be1760b5adb8410d5ffaaaed900961bba16fa22b`).
The original DB is retained in the same-prefix `-network/` directory; a copy
was reopened read-only for exact transaction inspection. The funder wallet's
`lt=43000001` transaction has successful compute/action and a 2 TOS outgoing
message hash `U85J/XVl+j5HX8G93CzC4iHQQ8wqSsFQO4LdeNK2y1A=`. The target
Agent Wallet's `lt=43000003` inbound hash matches, and its chain balance is
2 TOS. That account is not yet active, so its inbound transaction shows compute
skipped/aborted; this does **not** undo the credit. Raw RPC bodies are in
`test/integration/.e04-agent-wallet-c951856a6-20260925-forensic/`:
`funder-transactions.json` SHA-256
`05a9de43aed0a2eb95db92ca25aee02931f404153a1543b0e758ccc6749b4270`,
`agent-wallet-transactions.json` SHA-256
`ef465b282828462fd272f6910ea5a1623c7e478388fcbf95b7120406ca3fb95b`,
and `agent-wallet-info.json` SHA-256
`e6fbb9573e0dcc0d8230f764955be22d5cdf5429342e9f301946387c574ca246`.
Again, the CLI's 15-second seqno timeout was a false negative, not a failed
transfer; no ambiguous funding message was resent. `AgentWalletFundCmd` now
uses the same single-send exact-hash/destination confirmation. Its routing
control and six existing exact-confirmation tests pass 8/8, while restoring
the old one-send/short-seqno structure makes the routing control red. A new
fixed-tree E04 runtime run is still required.

The first run used committed `a0a9fd52b` with `TOS_BUILD_DIR=build`, `PYTHONPATH=test/tostester/src`, and the retained command `uv run python -u scripts/agent-wallet-account-e2e.py` under `script -q -e -f`. Its full output is `test/integration/.e04-agent-wallet-a0a9fd52b-20260925/console.typescript` (SHA-256 `3476e5dc07228dd9b30d38cda2ec169d51eb5981f656fe78a72a18187d0663c6`); process exit was 1. Six provision/status checks passed. The second invocation of `agent account native-prepare` for the same action failed with `ambiguous broadcast must be resolved from finalized state`. The node directory is preserved under that run directory's `network/`, not deleted.

That refusal follows `AgentAccountNativePrepareCmd::run`: after journaling the exact signed BOC, it calls `begin_broadcast` **before printing the BOC**. `ControllerActionJournal::begin_broadcast` refuses a second call while the record is Broadcasting. The first script assumed that invoking `native-prepare` again was an exact-BOC retry, but the safe retry is reusing the first printed BOC. Commit `be74e9cc6` changes the script accordingly and asserts the second preparation refuses for the precise ambiguity reason; it does not weaken production custody.

The second run used committed `be74e9cc6` with the same command and built binaries. Its output is `test/integration/.e04-agent-wallet-be74e9cc6-20260925-console.typescript` (SHA-256 `aefa245ec5624ab5cba03f4b4c993c68953843fd9abc06aaf50191eda2326883`), process exit 1, with the node directory preserved as `test/integration/.e04-agent-wallet-be74e9cc6-20260925-network/`. Twelve checks passed, including the exact ambiguity refusal, two submissions of one retained BOC, one destination credit over the observation window and exactly one consumed Agent Account seqno. The next `native-prepare`, for the cancellation scenario at the advanced seqno, failed: `controller sequence advanced while an exact action is unresolved; provide exact winner/effect proof before changing custody state`. This was before the cancellation, task-send, policy, rotation, restart and expiry checks. No ALL PASS claim follows.

The script SHA-256 at `be74e9cc6` is `c4b422a1d2ee962d97428f7aed1ca51bc4f5769e425f761fc1eeb38bbcf3f876`; validator-engine and tosctl binary hashes were `2b9c840dd17c00190774416c75061b9f6720a63f4f523ab9d1a88aa38abb38a8` and `5d9a333f927416688d1fc09f89673a2e4a15c8c0e02597d244d78af3fe1fb956`.

## Why a one-line fixture retry cannot clear it

`ControllerActionJournal::reconcile_finalized_state` rejects a sequence advancing past any unresolved exact action. The product `agent account native-resolve` requires the primary config plus at least two **distinct** single-endpoint RPC configs, compares exact finalized transaction observations by quorum and then records a resolved exact winner. The current E04 network has one node and one JSON-RPC endpoint; copying that endpoint under aliases would not provide independent chain views. The resolver's present search matches the primary submitted BOC and its outbound transfer, so it does not itself establish a cancellation-wins resolution. Clearing or replacing the custody journal to let later commands proceed would erase the protection this route needs to exercise.

## Minimal next decision and acceptance

The positive native Gift needs three real node/RPC views in the same local chain and a `native-resolve` call before a new action uses the advanced seqno. The cancellation-wins and expired-Gift negative controls then need either a production-supported exact cancellation resolution or isolation on separate account fixtures so an intentionally unresolved terminal action cannot block unrelated later lifecycle steps. This is a fixture topology and custody-workflow change, not a timeout increase. Before choosing an implementation, confirm whether E04 acceptance requires all controls on **one Agent Account** or allows separate accounts for terminal negative controls. Either way, the completed run must retain exact BOC/transaction evidence, the named custody refusals, controller rotation, policy update, restart and expired-action effects, with old-red/new-green and a source-bound report. Until then E04 remains OPEN.
