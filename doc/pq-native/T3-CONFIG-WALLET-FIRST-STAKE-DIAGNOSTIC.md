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
