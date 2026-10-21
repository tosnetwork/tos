# Token and NFT lifecycle rehearsal

Run from the repository root with the workspace Python dependencies installed:

```sh
uv run python scripts/tok01-local.py --runtime ../tok01-runtime --output ../tok01-evidence
```

Both destinations must be new. Build the production Release targets in the builder
image first: `gen_fif create-state fift func toslibjson validator-engine
validator-engine-console generate-random-id dht-server lite-client
tos-pq-consensus-key`. Pass `--build` when using another build directory.

The local launcher reuses `tostester.Network`, its genesis faucet and wallet
implementations. It uses global id 3, the deployment fee schedule, a fresh public
authentication namespace, one validator, dedicated loopback ports 28601 onward,
and JSON-RPC at 28680. It manages its nodes through user systemd units in the
`bailu-tok01.slice` aggregate (8 cores, 12 GiB RAM, swap disabled). Override
`--prefix`, `--base-port` and `--rpc-port` for another concurrent run. Maintain
a 40 GiB task disk budget and at least 200 GiB free; the launch preflight reserves
that headroom. The caller must monitor ongoing disk use. Stop only the dedicated
units through `systemctl`. Remove the disposable runtime after preserving public
evidence; it contains local signing material and must never be published.

The endpoint runner also accepts an existing endpoint and three funded sender
addresses:

```sh
uv run python scripts/tok01-lifecycle.py \
  --endpoint http://127.0.0.1:28680/jsonRPC \
  --output ../tok01-evidence \
  --owners ADDRESS_A ADDRESS_B ADDRESS_C \
  --sender-command './operator-signer-adapter'
```

The adapter receives a JSON object on stdin with `sender`, `message_boc` (an
unsigned internal message including optional StateInit), and `send_mode`. It
must sign and submit using the selected sender's supported wallet path and
return `{"submitted":true}` on stdout only after successful submission, with
exit code zero. It must keep signing material out of stdout and evidence.
Submission is subsequently checked through real destination transactions.
The harness owns no external keys and does not bootstrap or fund an external
network. Supplying an endpoint authorizes transactions; the local task does
not authorize a public run.

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

For epoch 5, pin the approved release and contract hashes, use its approved RPC
endpoint and supported signer adapter, fund the three wallets with test funds,
verify the new genesis/global id/authentication namespace and real fee config,
and obtain the separate live-run authorization. Rebuild/rehearse on that exact
release: this main snapshot precedes the pending basechain gas-credit change.
Preserve the resulting blocks for the separate cross-architecture replay case;
the local lifecycle runner does not claim that replay qualification.
