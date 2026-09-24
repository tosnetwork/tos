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
