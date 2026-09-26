# E07 Task Escrow retained route — 2026-09-25

Status: OPEN. The first exact-tree real-chain run did not reach the TIMEOUT control.

The `efc0ebe69cf26010daa6e2510ae346702875c5d6` run used
`script -q -e -f -c 'TOS_BUILD_DIR=build PYTHONPATH=test/tostester/src uv run python -u scripts/agent-task-escrow-e2e.py' test/integration/.e07-task-escrow-efc0ebe69-20260925-console.typescript`.
It exited 1 at 06:01:43 UTC after 50 PASS lines. The controller task was open, but
the first `agent task send --operation accept --via-agent-account runtime-agent`
was rejected before side effects: `--via-agent-account requires at least two
--quorum-config values before any Task side effect`. This is a harness/CLI
compatibility failure, **not** a contract refusal or a passing E07 run. The
console SHA-256 is `f875287866cca90f93d1647a7a723f125956e979ce386ed242dcb7eeb386e612`;
all node data is retained in
`test/integration/.e07-task-escrow-efc0ebe69-20260925-network/` (about 834 MB).
The script source on that tree hashes to
`fcfde9cc9b93cc84cc3443469f5d37e5a4d10d04075496faa0dfecd3616fba2a`.
The validator-engine, dht-server and tosctl binary hashes were, respectively,
`2b9c840dd17c00190774416c75061b9f6720a63f4f523ab9d1a88aa38abb38a8`,
`a55e3f16efc39a72e3c45f84bc4672b271f9be81d3e4612dbd019f077bff2937`,
and `bb60afd03c43519d43f0c3aed0b053110034bcac181d0b4ee6d8c284876316d1`.
All local script, validator and DHT processes exited; the old network was not
reused or overwritten.

The next source unit provisions two independent observer RPC nodes, each with
its own absolute single-endpoint tosctl config, verifies both follow the same
zerostate, and supplies both configs plus a distinct stable controller action ID
to each of five Agent Account Task actions. It does not weaken the CLI's
crash-safe quorum requirement. Its targeted non-network test has 6/6 passing;
omitting one call's expanded arguments fails at the call-site assertion, and
duplicating one observer config fails the two-config assertion. This is only
preflight evidence; E07 needs a new exact-tree chain run, retained premature
timeout wallet→escrow receipt and VM exit, final expiry/refund, fixed-head CI,
and independent review before signoff.

The exact committed `20a88c314cab1b8a387a681b122734dac6448854` rerun
provisioned three distinct validator-engine PIDs (one validator and two
observers), verified each observer against the same zerostate, and passed the
controller accept/result, claim/result, reject/refund and cancel/refund routes.
It reached the TIMEOUT path with the task `accepted`, then exited 1 at
`premature timeout control found multiple new transactions`. This is a
**forensic ambiguity in the control**, not a demonstrated Task Escrow VM
refusal or a passing E07 test. The raw console is
`test/integration/.e07-task-escrow-20a88c314-20260925-console.typescript`
(SHA-256 `9a514d51391d9f4148c88644bd6a07dd19f9f68c5bff5918a238e8a9dcfc7d42`);
the original node/config data and process map are retained under
`test/integration/.e07-task-escrow-20a88c314-20260925-network/`
(about 2.0 GB). All child processes exited. The source control counted every
wallet/escrow transaction after separately observed baseline LTs but did not
record those rows before raising. It therefore cannot yet distinguish a
lagging baseline/unrelated transaction from a duplicate Task send. The next
bounded diagnostic must save the exact pages and both baselines on this error
before changing the acceptance predicate or sending another test message.

The `764f7780901945f6320497eae7b7ae479839ce25` diagnostic rerun also
exited 1 at that deliberately unchanged guard. Its raw console is
`test/integration/.e07-task-escrow-764f77809-20260925-console.typescript`
(SHA-256 `1effcbb0834ac0707717e91051567efdeb8de3390ce14495af59d67b9c5c3914`);
its node data and the new raw receipt file are retained under
`test/integration/.e07-task-escrow-764f77809-20260925-network/`.
The receipt SHA-256 is
`e28288a8f1afe1d576398c2ae2f45ec117b547d6325db7cab686f56e63997822`.
It resolves the ambiguity: wallet LT `733000001` sent exactly one message to
the timeout escrow, hash `WzWjl8j4TNCRAQRnlBqCm55BnmDmCDiZBHl/dXEmMcQ=`;
escrow LT `733000003` received that same hash at chain time `1790319258`,
aborted with VM exit 109 before deadline `1790319303`. Wallet LT `733000005`
was **not another send**: its incoming message was a bounced credit from that
escrow, with no outbound messages. Both wallet transactions share a block
timestamp. The old instrument's `len(newer_wallet) > 1` counted the bounce as
a duplicate send. This was a false negative in the test, not a protocol failure.

The next code unit selects the unique wallet *outbound to this escrow* and
allows only a same-escrow bounced credit as an additional wallet transaction;
it still refuses a second outbound to the escrow, an unrelated wallet
transaction, or a second escrow transaction. A 9/9 targeted unit run covers
the genuine bounce and both refusal directions. The production code is
unchanged. This local diagnostic does not yet prove the script's later
expiry/refund and persisted-record checks, so E07 remains OPEN pending a new
exact-tree full run, fixed-tree CI and independent review.

The exact `841567229f442a7b39c7c8d53a385459a793f9f8` full rerun exited
0 at 07:17:36 UTC: 106 PASS, zero FAIL, `RESULT: ALL PASS`. Command:
`script -q -e -f -c 'TOS_BUILD_DIR=build PYTHONPATH=test/tostester/src uv run python -u scripts/agent-task-escrow-e2e.py' test/integration/.e07-task-escrow-841567229-20260925-console.typescript`.
The console SHA-256 is
`feaf2ff1b19e068b5c95fcd6ec362bece6c69b2c9e1a6eea36112fdf39960f97`.
Original node DB/config/process map and receipts are retained under
`test/integration/.e07-task-escrow-841567229-20260925-network/`; receipt
SHA-256 `a956eec46198b7095d738bb721b8dc69890f801f5ec80bd1eb32e26415ff6906`,
process-map SHA-256 `eb14ea3d3c611fc964a79984c53992e416487ecb4673b8bc6b7e92a227ac2bdc`.
The script and targeted test SHA-256 values are
`362c65db71a08a46c50c1858e24fbe63015032e3f885c24076f8b72d67a6dd8b`
and `3a0fbb65f3f45de5f6a9d24dfd1ce4a698982b40d5f715b662102da84a2ee455`.
The built validator-engine/DHT/tosctl SHA-256 values are the same as the efc0
run above; no production binary changed. All local child processes exited.

The premature control records wallet LT `723000001` outbound hash
`qbzJEObFiYe4PaBRr+s1gX6oSoZOx/kAANIOh7827X0=` and escrow LT
`723000003` inbound with the *same* hash, `aborted=true`, VM exit 109,
chain utime `1790320594` before deadline `1790320623`; the Task remained
`accepted`. A finalized masterchain header then crossed the deadline at
seqno 315 / chain time `1790320628`; the positive timeout, creator refund,
escrow drain, ten persisted records, and on-chain status/filter checks all
passed. This is a one-validator plus two independent-observer local PQ-chain
route, not a multi-validator or release-scale result. E07 remains pending
independent review and all required fixed-head CI terminal results; it is not
unilaterally marked complete here.

Mac's independent review found that the `841567229` control would also
accept an unrelated same-escrow wallet credit: it checked the bounced flag
and source but did not bind the credit to an actual outgoing message of the
specific aborted escrow transaction. `f21f0c726` requires the wallet send to
have exactly one total outbound, every additional wallet credit to match the
escrow transaction's exact bounce hash/source/destination with no wallet
outbound, and at most one such bounce. A mismatch preserves both raw transaction
pages in `e07-premature-timeout-ambiguous.json`. The 11 targeted unit controls
pass; deleting only the `bounce_hash not in expected_hashes` check makes the
wrong-hash full-control test fail because it incorrectly accepts the unrelated
credit. The retained mutant log is
`test/integration/.e07-bounce-hash-mutant-f21f0c726-20260925.log`, SHA-256
`5c3e6ee254ca320e6584faae166d7309adf486bcd31603a1846e8bd2ed225779`;
mutant script SHA-256 is
`e4a7798a313a0abbcffde3b24d2c891140646d1e06ac545ed470afee59f41ae3`.
The production source was restored before the full real-chain run.

The exact `f21f0c72606f3866d06b9692c4ab5dd58f141e2a` rerun exited 0
with 106 PASS, zero FAIL and `RESULT: ALL PASS`. Command:
`script -q -e -f -c 'TOS_BUILD_DIR=build PYTHONPATH=test/tostester/src uv run python -u scripts/agent-task-escrow-e2e.py' test/integration/.e07-task-escrow-f21f0c726-20260925-console.typescript`.
Console SHA-256 is
`9b458d8fe64d8fb70999ae3d1c43e59ab77663547d89ee33e477b4b9f3d37153`;
node DB/config and receipts are preserved under
`test/integration/.e07-task-escrow-f21f0c726-20260925-network/`.
The timeout receipt SHA-256 is
`8fb33f27128b5f1c74abb7f3dba206d36838f7222b83d206ff5edb6f76baf211`,
process map SHA-256
`68f58783032eaa70f29581c783e5dab407705b95dfca5a8c87eb7a37e207915d`.
Wallet LT `733000001` has the sole outbound hash
`0+lAhSTHa+Qg471ucnH20cdpWOeiPMBeb0aKdIOIRHc=`; escrow LT `733000003`
received that same hash, aborted with VM exit 109 at chain time `1790322839`
before deadline `1790322873`, and emitted bounce hash
`ptWHebXjimKt1fLlM9E+lBHtT4cd0YwxhwDZ62sS0Ko=`. The only additional
wallet row, LT `733000005`, receives that exact bounce and emits no message.
The Task remained accepted until the finalized head crossed the deadline;
positive expiry/refund and the later persisted-record checks passed. Script
source SHA-256 is
`f57ea5b664e6b8041a70016f23b189b0607b42aeb7438b5a75f89d959140f6d6`;
the targeted-test SHA-256 is
`730e312d5e0027bec4ab9f2307c37cc86c631c242305ffecc112eae9ce702d20`.
Validator-engine, DHT and tosctl binary SHA-256 values match the earlier
`efc0` run. No child network processes remain. This is still a one-validator,
two-observer local route, pending independent review and fixed-tree CI; E07
remains OPEN.
