# E11 three-round Stage A exact-tree run — 2026-09-25

Status: local full launch-gate PASS, pending independent raw review; E11 is
not self-signed by this report. Source and origin commit:
`d6bb1aaf19414827c4cb56a70f68e40705cd9b2b`, tracked tree clean.
Command:

```text
script -q -e -f -c 'PYTHONPATH=test/tostester/src uv run python -u scripts/validator-election-stage-a.py --mode launch-gate --stage a --build-dir build --output-root test/integration/.e11-stage-a-d6bb1aaf1-20260925' test/integration/.e11-stage-a-d6bb1aaf1-20260925-console.typescript
```

Exit code 0. Report
`test/integration/.e11-stage-a-d6bb1aaf1-20260925/20260925T093159Z/report.json`
has `status=pass`, `failures=[]`, and both source-commit fields equal the
fixed commit. Console SHA-256
`ad0798e49b929fc7bb7cd6ac2142a65f80fad6d09299d2fd48ffad7ee969d762`;
report SHA-256
`40833cd44a1f268c2e20dee4e7c9804c7301433504f2b360970a2f8f8f50b1fb`;
`artifact-snapshot/manifest.json` SHA-256
`2b081b9d7bbb01efc81a4f439aaf084c03b93826af4f08f4c5b9564de961d6d3`.
The complete run directory retains network logs, metrics, source/binary
snapshot, original pool-order BOCs, Config34/past-elections reads and
transaction/reply artifacts. All network/test processes exited normally.

The event ledger has 12 `pq_candidate_accepted` (four in each round),
first-round `pq_first_election_activated`, two later `pq_config34_activated`
events (second and rollover sets), eight `pq_pool_stake_recovered` (four
per completed old round), one `pq_full_launch_gate_passed`, duplicate-recovery
refusal, and `two_of_four_safe_halt_passed`. Election IDs are
1790329322 / 1790329622 / 1790329922. The first recovered credits are
four times 11002354208525 nanotons; second credits are four times
11002274333236 nanotons. Each recovery gate required the Elector reply,
credit deletion and pool balance increase. The local source guard and four
focused controls passed; old `2d7e4cd7d` live run refused second-round
validator 4 after elect_close, while this fixed tree accepted query 1004.

This is the script's accelerated, four-controller local PQ launch rehearsal.
It is not a release-scale, multi-host or arbitrary-crash result, and it does
not close separate E03 indexer ancestry/reorg risks or G-2 integration.
