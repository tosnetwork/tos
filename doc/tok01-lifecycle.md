# Token and NFT lifecycle rehearsal

Run from the repository root with the workspace Python dependencies installed:

```sh
uv run python scripts/tok01-local.py --runtime ../tok01-runtime --output ../tok01-evidence
```

Both destinations must be new. The local launcher requires a clean tracked source
tree, including the staging area, before starting nodes. The harness binds the
run to that commit: it writes `provenance.json` with a run identifier before the
first step and marks it complete only when the same clean head is observed again
after the last step. Commit source changes before collecting evidence. Build the production Release targets in the builder
image first: `gen_fif create-state fift func toslibjson validator-engine
validator-engine-console generate-random-id dht-server lite-client
tos-pq-consensus-key`. Pass `--build` when using another build directory.
Generate the existing Python protocol bindings once with
`uv run python test/tostester/generate_tl.py` before importing the local launcher.

The local launcher reuses `tostester.Network`, its genesis faucet and wallet
implementations. It uses global id 3, the deployment fee schedule, a fresh public
authentication namespace, one validator, dedicated loopback ports 28601 onward,
and JSON-RPC at 28680. It manages its nodes through user systemd units in the
`tok01-lifecycle.slice` aggregate (8 cores, 12 GiB RAM, swap disabled). Override
`--prefix`, `--base-port` and `--rpc-port` for another concurrent run. The task
owns a 40 GiB disk budget that must stay above the 200 GiB shared free-space
floor, so the launch preflight refuses to start with less than 240 GiB free. The
caller must monitor ongoing disk use. Stop only the dedicated units through
`systemctl`. Remove the disposable runtime after preserving public evidence; it
contains local signing material and must never be published.

When the host libc is older than the builder's, run Python in the builder image
and pass `--runtime-libraries` pointing to its copied dynamic loader and required
public shared libraries. Mount matching absolute workspace paths and the user
systemd bus into that container. The systemd services execute native nodes with
that loader, so systemctl owns the actual node processes. In this mode the node
slice is capped at 6 cores/10 GiB; cap the Python container at 2 cores/2 GiB so
their combined budget remains 8 cores/12 GiB.

The endpoint runner also accepts an existing endpoint and three funded sender
addresses:

```sh
uv run python scripts/tok01-lifecycle.py \
  --endpoint http://127.0.0.1:28680/jsonRPC \
  --output ../tok01-evidence \
  --owners ADDRESS_A ADDRESS_B ADDRESS_C \
  --sender-command './operator-signer-adapter'
```

Before any transaction the runner reads the network identity (ConfigParam 19)
from the endpoint and refuses unless it is listed: only the local id 3 is allowed
by default, and any other network needs an explicit `--allow-global-id` for that
exact value. The local launcher reads the identity from its own node the same
way. The identity is recorded in the provenance. The adapter receives a JSON
object on stdin with `sender`, `message_boc` (an unsigned internal message
including optional StateInit), and `send_mode`. It must sign and submit using
the selected sender's supported wallet path and return `{"submitted":true}` on
stdout only after successful submission, with exit code zero, within
`--signer-timeout` seconds (120 by default). The adapter runs in its own process
group; on the deadline the whole group is killed and the run fails, and because
the adapter may already have submitted, the state of that submission is unknown
and must be checked on chain before any retry. It must keep signing material out
of stdout and evidence. Submission is subsequently checked through real
destination transactions. The harness owns no external keys and does not
bootstrap or fund an external network. Supplying an endpoint does not by itself
authorize a public run: the network must be allowed explicitly and the separate
live-run authorization still applies.

The contract code comes directly from the release SDK's generated Token
constants and NFT constants. These match the SDK wrapper layouts; the native
TOL Token family is a separate deployment choice. `contracts.jsonl` records
addresses and code hashes. No compiled constant or pinned evidence is changed.

The runner mints 1,000 and 100 token units, transfers 100 to an existing wallet,
50 to a new wallet and 25 with a notification and payload, attempts an
insufficient-balance transfer, burns 10 and changes admin. It deploys an NFT
collection, mints item 0, transfers it and submits a non-owner transfer.
Three sender wallets receive 10 TOS each in the local run. Each operation
attaches 0.5 TOS; forwarded mint/item funding is 0.2 TOS.

Evidence includes public RPC requests/responses, raw transaction BOCs and their
full block IDs, getter/RPC field comparisons, expected balances and supply,
notification payload checks, persistent-data equality after refusal, and bounce
accounting including the forwarding remainder and storage fees charged against
the previous contract balance. A refusal still pays native transaction fees;
unchanged state means unchanged contract data and asset ownership/balances.
Index methods expose membership and wallet/collection references; fields absent
from their schema (including Token wallet balances) are recorded through getters,
not invented as RPC fields. The output must be reviewed for any gaps before
claiming full TOK-01 acceptance.

These two entry points are needed because the existing wallet-index runner
tests genuine versus forged indexing, has fixed local paths/ports and does not
implement the asset lifecycles. Existing SDK code constants and transaction,
wallet, genesis and process abstractions are reused instead of adding another
signer, contract compiler or network implementation.

For a public network run, pin the approved release and contract hashes, use its
approved RPC endpoint and supported signer adapter, fund the three wallets with
test funds, verify the genesis, global id, authentication namespace and real fee
configuration, allow that global id explicitly, and obtain the separate live-run
authorization. Rebuild and rehearse on that exact release first. Preserve the
resulting blocks for the separate cross-architecture replay case; the local
lifecycle runner does not claim that replay qualification.

Independently verify retained evidence and exercise the oracle with mutations:

```sh
uv run python scripts/tok01-oracle.py ../tok01-evidence \
  --expect-source-head <commit> --expect-global-id 3
uv run python scripts/tok01-oracle.py ../tok01-evidence --red-controls
```

The verifier reports the source head, network identity and run id it accepted,
and the two expectations make it refuse evidence sealed at another commit or
taken from another network, so a clean run at an older head or on an explicitly
allowed public network is never reported the same way as the intended one.

The verifier requires all 13 lifecycle steps, their comparison tables, supply
invariants, transaction hashes/full block IDs, both bounce receipts and the
notification receipt. The red controls use copies of measured receipts, first
validate each baseline, deliberately corrupt one property, require failure and
then revalidate the original. They never modify retained evidence. Controls
cover expected supply, wallet sum, a negative balance that still conserves the
sum, comparison fields and flags, notification payload, refused-state equality,
bounce accounting/receipt completeness, transaction identity and block identity.

## Receipt acceptance guards

The independent oracle requires the exact ordered lifecycle labels in the step,
summary and invariant records. Every step records its sender, its destination,
the hash of the message it sent and the transaction that consumed exactly that
message: the runner selects the receipt by the sender's outgoing message hash, so
a bounce or an unrelated inbound message on the destination can never stand in
for it, and the oracle checks that binding from both ends by decoding the
retained transaction BOCs themselves: the target's inbound message hash and
account, and the sender transaction's account and outgoing message hashes with
their destinations. The RPC rendering of those edges must agree with the decoded
transactions, so a rendering that relabels an unrelated real transaction as a
lifecycle step is refused. The oracle holds its own table of expected outcomes (exit 0 everywhere
except 706 for the insufficient-balance transfer and 401 for the non-owner NFT
transfer) and decodes each target's compute exit code, aborted flag and action
result from its hash-checked transaction BOC, so the outcome does not rest on the
RPC rendering or on the runner's summary; the rendering the runner compared
against must agree with the decoded transaction. It requires `provenance.json`
to be marked complete, to carry the same commit before and after the run, to
name the network identity and to belong to the run that wrote the summary. Older
receipts without these fields need a fresh rehearsal; they must not be edited to
simulate evidence the runner did not collect.

Token and NFT membership checks wait for `index_state.complete == true`, including
absence checks. Missing or false completeness eventually fails the rehearsal. Once
a step has deployed the token master or the collection, or minted the item, every
later snapshot requires that contract to be active.

Run `uv run pytest -q test/tostester/tests/test_tok01_review_guards.py` for the
52 offline guard tests. They use synthetic records, mocked RPC responses and
three retained sender/target transaction pairs from a disposable local network
(`tok01_fixture_transactions.py`, one per outcome class) so message-edge and
outcome decoding are exercised; they are not native lifecycle evidence. Removing
each of the step, destination transaction, decoded message edge, sender binding,
decoded outcome, provenance, expectation, network, signer-deadline, clean-source
and index-completeness guards makes its targeted tests fail; restoring the
guards passes all 52. `tok01-oracle.py --red-controls` additionally exercises
step duplication, label replacement, empty transaction sets, wrong destinations,
tampered renderings of outcomes and message edges, a swapped target transaction,
a relabelled sender transaction, a missing sender message and tampered
provenance against fresh native receipts; each control must turn red for its
stated reason, not merely fail. A new native rehearsal is required for
acceptance of this revision; previous retained receipts describe their recorded
source only.
