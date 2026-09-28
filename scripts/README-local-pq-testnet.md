# Persistent local PQ network

`sudo scripts/setup-testnet.sh --clean` creates a fresh development network:
four PQ validators, two non-validator observers, a DHT, an independent
lite-client and the development shielded pool. `--build` rebuilds its binaries.
`--clean` deletes the existing `/data` network, keys, state and node file logs.

## Ten-minute elections

Add `--rotate` to enable real Elector elections with Config15
`600 / 300 / 60 / 180` (elected period / election lead / election close lead /
stake holding period, in seconds). The initial set also expires after 600
seconds. This mode admits the production PQ controller code in Genesis and
uses disposable deterministic development controller/consensus keys.
It must never initialize a production chain.

The initial active set is nodes `1,2,3,4`. Node `7` is a fifth candidate process,
not an additional Genesis validator. The `tos-pq-elections` service submits
node-authorized pool stakes for `1,2,3,7`, then `1,2,3,4`, alternating each
round. Exactly four candidates enter each election. Nodes `5,6` remain ordinary
observers. All five candidate processes stay online, including the retired
member, so absence of its first-hop traffic is evidence of relay selection
rather than a disconnected destination.

The operator wallet, controller and pool transactions use local test funds.
The service checks each Elector acceptance and retains the submitted roster;
acceptance is not an activation verdict. The chain itself selects and activates
the next set. The development faucet supplies fresh pool capital each round;
this service is not a production staking/recovery manager. It deliberately does
not automatically restart after an ambiguous transaction failure.

## Inspect and verify

```sh
scripts/testnet-ctl.sh status
scripts/testnet-ctl.sh check
sudo journalctl -u tos-pq-elections -n 30 --no-pager
sudo env PYTHONPATH=test/tostester/src:scripts .venv/bin/python \
  scripts/check-local-pq-relays.py --output /data/elections/relay-verification.json
```

Evidence lives under `/data/elections`: Config15 bytes, candidate public
identities, actual node authorizations, Elector acceptance events, agreed
Config34 bytes at one common height on seven full nodes, and raw two-step
broadcast trace lines. Console credential files and fixture key seeds are
private; do not publish them.

The relay checker requires a real one-member replacement, a 600-second elected
interval, and every current validator's broadcast to target exactly the other
three current validators. The same broadcast ID/content hash must finish on
all three receivers. It excludes 20 seconds of in-flight work after observing
activation. Retired members may still receive second-hop broadcasts; that is
separate from eligibility as a first-hop relay. Four active validators exercise
the simple two-step path, not the five-relay FEC threshold.

Tests: `PYTHONPATH=scripts uv run python -m pytest scripts/test_local_pq_elections.py`.
