# E13 Service Actor indexer cursor investigation

The exact `f881e8d0a5d2425dde45e43c1b413af000110cc6` run used
`TOS_BUILD_DIR=build PYTHONPATH=test/tostester/src uv run python -u scripts/service-actor-e2e.py`
under `script -q -e -f -c`. It exited 1 with 80 PASS and six FAIL. This is a
failed E13 run, not acceptance evidence. All process-owned node and daemon
artifacts were retained under
`test/integration/.e13-service-f881e8d0a-20260925-network/`.

| Raw artifact | SHA-256 |
| --- | --- |
| `test/integration/.e13-service-f881e8d0a-20260925-console.typescript` | `3fced6594ba257aa7c197eb56bf5c83ef8b79bf633c2774a11bbeea7b4792a33` |
| `provenance.json` | `d573c43d9fca2de25f6bf25c13b05f69ed5aba27ec2cb91bd7134f2301a7d7c4` |
| `negative-evidence.jsonl` | `356663c5db108fa9f5788d397ada76aa70f627b27185224d72e399e6be39b203` |
| `positive-evidence.jsonl` | `8d4d9aab2db37af194f7f23a7b766ecc436abe98eb32aee73b1beb0b21d95b4f` |
| `http-transcript.jsonl` | `5520b4db65c5f66327fb54511c0690d1d6735c53cd6cc68c60cab375900207cd` |
| `rpc-transcript.jsonl` | `6884cee6c210ada7d351981e97f89e077a013e00bb81fb35dd013d3fd2804010` |
| `cli-transcript.jsonl` | `39f88842f433ff544aaa720e66a7ee9dd4f67c47208ea589c1e19796c3b20855` |
| `tosctld-service.log` | `0e0ba24b5918cd2fdb8d95b25cad42875ffd1d64eb8b191cde8da9ae9b1583ad` |

The first five FAILs were `/services` empty and service detail 404/empty
fields, despite a successful deployment. The deployment receipt's two later
finalized masterchain heads were seqno 46 and 47. The background indexer
started from an empty SQLite DB and was still traversing history during the
script's fixed 60-second discovery poll. It subsequently stored the same
Service Actor in `indexed_contracts`, and a live `/services` read returned it.
The daemon's separate `contracts` task also logged a zero-balance master
wallet every two seconds; `service_main_task.rs` starts `indexer` in its own
TaskController, and the retained SQLite checkpoint advanced despite those
errors. Thus the wallet error does not by itself explain the empty index.

The sixth FAIL was request B's HTTP lifecycle status
`resolved_or_unknown` instead of `responded`. The request endpoint in
`agent_query_api.rs` serves live `get_request` for pending items even when
there is no stored index row. At final cold inspection, the retained
`service_request_lifecycle` table held request 0 as `responded` but had no
row for request 1. This is consistent with the indexer's snapshot scanner
first reaching request 1 after it had resolved; it cannot infer a terminal
status for a request it never saw pending. It is not evidence of failed
Service Actor execution: the CLI/on-chain response checks passed. The exact
indexer tick that first saw request 1 was not captured, so the timing link is
an inference from source and retained state, not a claimed actor trace.

The follow-up test change gates service discovery and both pending-to-response
transitions on `/explorer/status.masterchain_indexed` covering a *fixed*
finalized masterchain height observed before each transition. It records the
cursor and target in `indexer-evidence.jsonl`; a live chain head alone cannot
satisfy the gate. If the scanner fails to reach a target within the bounded
window, the route fails explicitly. This is a cursor prerequisite, not a
blind extension of the old 60-second poll. E13 stays OPEN pending a new
committed-tree real-chain run and independent review.

The first `9d754b254` cursor-gated run also failed before its deployment
barrier could finish: one `/explorer/status` HTTP read hit the 8-second socket
timeout, which the initial gate let escape. The retained console is
`test/integration/.e13-service-9d754b254-20260925-console.typescript`
(SHA-256 `c5875903bbdb6a8f91d19dc8493202c127f9bfb90d8d19c8342f588ac0977206`),
with network artifacts in the same-stem `-network/` directory. Its raw HTTP
transcript SHA-256 is `a373d8ea275cfeda89eb46ff000b6117c1479b374d58ccc25cb320a4b894fa3c`;
it contains ten successful `/explorer/status` responses before the unrecorded
transport timeout. This is neither a completed 300-second cursor timeout nor
a lifecycle result. A follow-up records each transport error and retries only
within the original total cursor deadline, with persistent-timeout refusal.

The next exact `b6486b7b3` run exited 1 with 89 PASS and one FAIL. Its
console is `test/integration/.e13-service-b6486b7b3-20260925-console.typescript`
(SHA-256 `bd3baa0053346ac8a51d4f2d0077894e2546fe86b74059dc8306744a8ae3e39e`);
all network artifacts are in the same-stem `-network/` directory. The
`indexer-evidence.jsonl` SHA-256 is
`2ea6d03114ffcbdf61bc71d7f9e6617cb461bdb39941fb9e06863b49c8fab9fb`,
the HTTP transcript SHA-256 is
`d940f9d86302c6991a8342c5eacd3bb93ab489b228ebd36ff71b4f129c9288da`,
and the retained SQLite DB SHA-256 is
`ce5280ea4206ff843e0775082b7f2434184c9d92300623be363e3b313206c58a`.
The four fixed-height cursor gates passed; both B and A terminal `responded`
statuses passed. At the intermediate point where B was `responded` and A
remained pending, the script made one immediate HTTP read of A and received
504 `get_request query timed out`. That single read was the sole FAIL; the
on-chain `request_show` had just confirmed A still pending. This is an
observation failure, not evidence that B's response changed A. The follow-up
uses the existing bounded state predicate poll for A and makes that poll
retry only transport errors within its original deadline. It never accepts
504 as the expected state; persistent 504 remains red.
