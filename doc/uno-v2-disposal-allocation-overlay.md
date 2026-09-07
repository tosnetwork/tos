# Disposal in the private multi-account allocation overlay

This is M1 integration work, not M1 acceptance or a production activation gate.
The explicit disposal overlay now prepares the coordinator transaction once,
uses its actual outgoing count to finish the common LT schedule, and builds the
other participants, AccountBlocks and final-import records on private accounts.
The strict existing entry still rejects destinations outside its role set.

Balances, transaction fees and exported value are decoded from serialized
Native artifacts. Exports include message value plus the remaining forwarding
fee, with checked currency arithmetic. Dictionary indices are contiguous and
message LTs must match the checked participant schedule. Replay independently
rebuilds account roots, AccountBlocks, InMsgDescr and end LT. Export vectors and
import-credit maps are derived caches: replay returns its own reconstruction.
The source account dictionary is not published or mutated on a later failure.

The explicit entry requires an unsplit shard. The coordinator lookup follows
the prior exact write-set check, which proves that its iterator distance is
nonnegative and below the account vector size. Each output index has passed a
15-bit dictionary-key check before conversion to the Native unsigned index.

## Boundaries still to integrate

- No production collator or validator calls this disposal overlay yet. Inputs,
  configuration and old accounts require source-aware admission/authentication.
  The dictionary decoder retains legacy VM-to-Status conversion; this helper is
  not the final voting error classifier. No new exception conversion is added.
- Native exports are actual message/transaction/index/LT tuples, not completed
  OutMsgDescr or queue evidence. The Native host must assign metadata, preserve
  actual-source DispatchQueue/FIFO rules and reconstruct queue insertions.
  A bounce source can differ from the coordinator. Existing transaction-account
  deferral context cannot silently substitute for actual-source ordering.
- Custody payouts, bounce/return authorization, unexpected-bucket liabilities
  and sweep authorization are not supplied by this allocation primitive. A
  nonempty payout effect is still rejected. Native cash availability does not
  authorize spending a bucket's liabilities.
- This does not alter the retirement rule: retain the descriptor, parameter 84
  entry and custody. Economic settlement does not terminate Native messages.

## Validation scope

The existing NativeDisposalEntry test now exercises the real two-participant
overlay with an untouched third account, two outgoing bounces, retained value
and opposing internal allocations. It checks balances, message and transaction
identities, LT intervals, independent replay, four altered root/schedule claims,
cache reconstruction, the strict legacy entry, a split identity and a later
insolvent custody participant. This is not a network or live CellDb commit test.

Rebuilt manual removal controls and restored test results are recorded in
`doc/measurements/uno-v2-disposal-overlay-evidence.json`. They are manual evidence,
not a recurring mutation CI gate. The normal test remains in test-workchain-block.
No consensus-judgement source file or error classification changes in this unit;
the independent review is due at the M1 milestone under AGENTS.md.
