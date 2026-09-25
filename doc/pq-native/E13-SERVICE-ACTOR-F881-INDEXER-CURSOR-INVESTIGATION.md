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

The committed `faaefd59d278f7ebc7f4921a1730007469a05aec` follow-up ran
the same serial, single-validator local route with
`TOS_BUILD_DIR=build PYTHONPATH=test/tostester/src uv run python -u scripts/service-actor-e2e.py`
under `script -q -e -f -c`. The wrapper exited **0** with **90 PASS, zero
FAIL**, and `RESULT: ALL PASS`. Its in-run `provenance.json` binds the exact
script, contract, `tosctl`, validator-engine and other binary hashes to that
source commit. The fixed cursor gates passed before discovery and request
classification. In particular, after B was indexed as `responded`, A's HTTP
status was observed as `pending` before A's own response; A and B were later
both indexed as `responded`. The raw HTTP transcript contains three HTTP 504
responses for A's request endpoint before the successful pending observation;
they were retried, not counted as a pending state. It also records 22
`/explorer/status` socket timeouts during cursor polling. The daemon's
separate contracts task continued to log its unfunded master wallet; the
indexer nevertheless advanced through every required fixed height. During
the script's deliberate daemon shutdown, `tosctld` required a kill after the
grace period and exited `-9`; this is visible in the console and is not
presented as an independent graceful-shutdown proof.

| Retained artifact | SHA-256 |
| --- | --- |
| `test/integration/.e13-service-faaefd59d-20260925-console.typescript` | `8bb6c5598e8cf9492ff43eee7ab299f9c8b92ceb15e5dbf73399e8f9eff2ad00` |
| `-network/provenance.json` | `3d8f42d6e54f7bef3f993da124585dd8e39d71ff19e483cfbf5179582749aaf9` |
| `-network/indexer-evidence.jsonl` | `14be75408eaa5cc8e61ce67a3bd724adf68c85c8c318f3000ba6b466e4e34060` |
| `-network/positive-evidence.jsonl` | `15fde09b05238cb84e12d430778c16affc085b066c0a1a10b45d4bd619e5c417` |
| `-network/negative-evidence.jsonl` | `ed4439753b882def3053d94ba4b1e211133e4aba160818287f9483777aa1750b` |
| `-network/http-transcript.jsonl` | `8a4f33c2f4087fe18bba83005f42bdaeb504d767b3a6d2978e5a872bbbb0a52f` |
| `-network/rpc-transcript.jsonl` | `d01c06fce7586a3cb852e31876525a382955d1fa76c074d22b56a917f9e4b55c` |
| `-network/cli-transcript.jsonl` | `09625f650a824e9d83c97aca1981130144f8ab8f0a719e82c2410e398a882e03` |
| `-network/tosctld-service.log` | `4ef374c240bce17614ac9f5721ac0d456066d48f015a6576e429784a1f1016cd` |
| `-network/tosctl-indexer.db` | `d7fb6c8ad83dcf15b3b60036016c955543670c9d11b32158043f0099e94e58ec` |

The `-network/` files are all under
`test/integration/.e13-service-faaefd59d-20260925-network/`. The test
processes exited and no validator or service daemon was left running. This
is local route evidence, **not** multi-validator, transport-authentication,
release-scale, or arbitrary crash-recovery evidence. E13 remains OPEN until
independent raw review and the owner's scoped signoff.

Subsequent provenance review found the **exact original faa Fift and Func
executables**, contrary to an initial missing-snapshot assessment. The retained
E11 Stage A snapshot at
`test/integration/.e11-stage-a-d6bb1aaf1-20260925/20260925T093159Z/artifact-snapshot/build/crypto/`
contains `fift` SHA-256 `37e0b3be30e96faf99db7061917dcf3a3950fd1ae1a6c8a7524ee52c0c0280ef`
and `func` SHA-256 `d47ff59584adb975d8b813542b1b2aef7a3caf0320ec30008696b673a9dec5fd`.
Both equal the original faa in-run provenance. Mac independently checked
those bytes, the other three named binaries, fixed source and raw receipts;
the owner then signed E13 for the **single-validator local route** in
memo/main `7c9d46fa`. Later shared-build Fift/Func changes do not retroactively
invalidate the original chain run.

An already-started second serial run from exact source
`8d87f75446c64e975471c63acca5b63d03732765` also exited 0 with 90 PASS,
zero FAIL and `RESULT: ALL PASS`. Its five execution binaries were copied
*before* network boot to
`test/integration/.e13-service-8d87f7544-20260925-binaries/` and their
file hashes match that run's `provenance.json` individually. It is independent
supplemental evidence, not the prerequisite for the prior scoped signoff.

| Supplemental artifact | SHA-256 |
| --- | --- |
| `test/integration/.e13-service-8d87f7544-20260925-console.typescript` | `5a9f164edf729ee952efd366a3423f7b19de7e71a7ca608ced98bc0a831ff35a` |
| `-network/provenance.json` | `5f44f95956b8780e41f5404b20ade3b2cb5a68fbfd35933ca75c46d975fe919c` |
| `-network/indexer-evidence.jsonl` | `d794e0c24c81427187a8426d305ec885030fac6e97d9a4a0768a762e683a3431` |
| `-network/positive-evidence.jsonl` | `b0837ecd214c1f7488fc0fc2b523aeea1113b430bc7e69ef41fe81c1ed04c530` |
| `-network/negative-evidence.jsonl` | `8a07d9db656c789884c950e1b572ea15101740a08d7c413b923f132d94ac41eb` |
| `-network/http-transcript.jsonl` | `7cd9289d7bc18c57245f71c650a32cc7ec53e6ef4342bd743629045c7b4cfc5e` |
| `-network/rpc-transcript.jsonl` | `ff3d8f618c9557eab1aa81d24dd840ac8a8c3a292a5871908397ae880419de81` |
| `-network/cli-transcript.jsonl` | `4b7e8d8e7acde425b6f26aa20b427febc4fd8a64467ac3ea124623b027e51fef` |
| `-network/tosctl-indexer.db` | `af224518be1c5debf6c2954c118d048be110036bf4106b7973467e775f242beb` |

The `-network/` files are under
`test/integration/.e13-service-8d87f7544-20260925-network/`. The five
frozen binary SHA-256 values, in `provenance.json` and the retained copies,
are `fift` `5ab4ddcb586ca130dec69b1c40e513c666d2948e0ab720e73ff3529a2b4787d6`,
`func` `3186336baa0d34d3efa59da0157093ba30dad0be3d448801ca1656411d771983`,
validator-engine `2b9c840dd17c00190774416c75061b9f6720a63f4f523ab9d1a88aa38abb38a8`,
DHT `a55e3f16efc39a72e3c45f84bc4672b271f9be81d3e4612dbd019f077bff2937`,
and tosctl `bb60afd03c43519d43f0c3aed0b053110034bcac181d0b4ee6d8c284876316d1`.
