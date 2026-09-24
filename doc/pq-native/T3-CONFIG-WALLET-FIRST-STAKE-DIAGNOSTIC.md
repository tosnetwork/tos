# Config-wallet first-stake diagnostic (2026-09-24)

This remains a diagnostic, not T3 product acceptance. The fixed-tree run at
`580ae4d95e686a5646a328089a12b86b3f27810a` ended with `passed=false`:
`test/integration/.pq-tosctl-config-wallet-product/20260924T055013Z/report.json`
has SHA-256 `7a8a477b5e2faaaae48c799b14cd4c377626bc4336338ea0485514bc79fcdd18`.
The CLI printed `Message delivered` and then failed while parsing
`participant_list_extended` with `stack cons list has a non-null tail: index=4`.
That CLI failure is not an Elector refusal.

The pool order's query ID was `1790229438`. The bounded pool scan was complete
(2 transactions, 1 page); its raw JSON has SHA-256
`9ddf8acc9df28eb60c446016f9d18ee256a00cddf0443fb2422c5c093cd99231`.
One pool inbound transaction was from the Elector, at chain `utime=1790229438`.
Its body decodes to opcode `0xf374484c` (`STAKE_ACCEPTED`), query ID
`1790229438`, and reason `0`. The controller scan was also complete (1
transaction, 1 page), SHA-256
`fd8b75892b093d0a671ed3daf72096b3aaac26f5ae9ae536e6fa028937bd1f63`;
it shows the controller forwarded the stake to the Elector. The report's
`elector_reply=null` was a recorder bug: it searched controller transactions,
but the Elector answered the stake-owner pool. The recorded raw transactions,
not that null field, establish first-stake acceptance for this diagnostic run.

Before changing the stack parser, a read-only `runGetMethodStd` call against
the same live chain captured an empty `participant_list_extended` result at
masterchain height 357. Index 4 was `tvm.stackEntryNumber` with decimal `0`,
`exit_code=0`. The full response is
`participant-list-extended-raw-preopen.json` in that run directory, SHA-256
`2c08e252708618532a6e0e1f62415ceb70939f6cd51c2c16e444957645e8462b`.
The contract's empty-election branch returns FunC `nil`; the node serialized
that nil as numeric zero, not as `tvm.stackEntryUnsupported`. The non-empty
index-4 raw response was not captured in this run: the CLI error and source
show a cons-list tail mismatch, but its precise raw shape remains to be saved
on the next fixed-tree run. The production parser change therefore accepts
only numeric zero as nil (including a proper cons tail) and refuses nonzero
numbers; it does not turn arbitrary malformed stack entries into empty lists.

No live ConfigParam 34 controller/ADNL pair was captured after this accepted
stake. The product path remains OPEN until a fixed-tree run records that pair
as well as the exact `STAKE_ACCEPTED` response. The separate election-daemon
caller remains OPEN independently.

## Follow-up at `8099fca98` (still diagnostic)

The exact-tree report
`test/integration/.pq-tosctl-config-wallet-product/20260924T060612Z/report.json`
has SHA-256 `7c093e044d4c0e71237502979511b2d37aee299f9678d783bd7613052faf25e3`.
Its bounded histories are complete (pool 2 transactions, controller 1; one
page each). The corrected pool lookup recorded `STAKE_ACCEPTED` with reason 0
for query ID `1790230397`. The CLI nevertheless exited at
`stack cons list has a non-null tail: index=4` after broadcasting the wallet
message. The run did not reach ConfigParam 34 selection.

The saved raw stack at the *pre-order* open election had index 4 encoded as
`tvm.stackEntryNumber(0)`, SHA-256
`415d0f1c89fe96f802043d980f0c42066d5390f432c83780d1caf7a323971c80`.
That observation only confirms the empty participant list before the order;
it does not identify the tail of the post-order nonempty list that made the
CLI fail. The next probe saves the full raw stack immediately after the CLI
returns, including on error, before changing the parser further. No
post-order encoding or cause is asserted from the pre-order sample.

The `0db8eaba3` follow-up report at
`test/integration/.pq-tosctl-config-wallet-product/20260924T061507Z/report.json`
(SHA-256 `5b0020c4473a131a899f5a4cb3b870ad8c974288efe1cee9e77b85ecc3e1866d`)
again records exact `STAKE_ACCEPTED`, reason 0, this time for query ID
`1790230929`. It also records that the immediate *post-CLI* JSON-RPC query
returned numeric zero at index 4 (raw SHA-256
`3b11c994d95ead584ddbecdbeacba4f80456195cf3f7329e61838270d65572b3`).
Because the CLI itself had just failed while walking a nonempty cons list,
that second query did not sample the same chain state. It cannot identify the
tail that caused the failure. The next diagnostic must report the tail from
the exact StackEntry being parsed, not from a later RPC call. This is a
measurement-timing limit, not evidence that the parser should accept all
tail types.

The diagnostic at `a7109b87e` settled the tail type without changing list
acceptance. Its exact-tree report
`test/integration/.pq-tosctl-config-wallet-product/20260924T062425Z/report.json`
has SHA-256 `cab9359cf2745a3d31119dcd2148374bfcaabd7243114eda0b1ac2f9c226b442`.
The parser's same-response error names the rejected tail as
`Tvm_StackEntryList(StackEntryList { list: Tvm_List(List { elements: [] }) })`.
The same report contains the pool's exact `STAKE_ACCEPTED`, reason 0, for query
ID `1790231489`; ConfigParam 34 was still not checked because the CLI exited.
The pre-order root was numeric zero and is a separate encoding observation,
not evidence about this tail. In `crypto/vm/stack.cpp`, null satisfies
`is_list()`, and the JSON-RPC stack renderer serializes it as an empty
`tvm.stackEntryList` at a cons-chain tail. The parser now accepts that exact
empty-list terminator, while rejecting a nonempty List tail and other
malformed tails. The unit test asserts both values and the two-element cons
ordering; removing the terminator arm or negating its emptiness check makes
it red. A new fixed-tree product run is still required for a successful CLI
exit and live ConfigParam 34 controller/ADNL pairing.

## Product outcome at `ca842b0f1`

The fixed-tree run
`test/integration/.pq-tosctl-config-wallet-product/20260924T063630Z/report.json`
has SHA-256 `b5a448040fd75f5f55e206751f86831cf68b3c2de5d3f84fdca236e2447a693d`:
`passed=true`, `failures=[]`, and the actual `tosctl config wallet stake`
command exited 0 after printing `Stake accepted by elector`. This is the
interactive config-wallet product caller, not the election daemon.

The pool's bounded history (2 transactions, 1 page, complete; SHA-256
`cb7ff3455740eea4b891af5eef3818d6a3ca29779b79331bcca64a0bf0ce919c`)
contains an Elector inbound body with opcode `0xf374484c`, exact query ID
`1790232216`, and reason 0. The controller history (1 transaction, 1 page,
complete; SHA-256
`2606351734e86e6899d4b425a8be35357313316abbdcbda5b2bf4f5dcf1a0f0f`)
has the matching `0x5051726c` relay and ADNL
`d2b806d6ea1a30dbdd09c75c633cc409cd8c25493ff7b808a3e4edfb718d3e03`.
Live ConfigParam 34, raw SHA-256
`f1ec118c1c388c01b72fb51f39985a2c0f1511599d3767d75a6d50b7f2fbf8ac`,
activated at `utime_since=1790232395` and lists four PQ validators. Its
controller record pairs
`dae8de3bc465a977f3c2c40efa33f89d463b46a1c9498e17a19a0603101c57d8`
with that same ADNL. The source of the ADNL is the actual controller relay,
not a fixture key assumption. The ConfigParam 47 read-back, imported original
StateInit, and binary hashes are retained in the same report. The compiled
test's numeric-nil and strict two-cons/empty-List controls cover the parser
condition that previously prevented the CLI from completing.

This closes the interactive config-wallet caller's first-stake acceptance and
live selection evidence on a co-located diagnostic chain. It does not prove
the election daemon's independent caller, a production controller-deployment
command, or release-scale operation. T3 and the two-caller correctness
question remain OPEN.
