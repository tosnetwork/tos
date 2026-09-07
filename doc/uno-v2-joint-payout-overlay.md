# Joint payout/disposal write-set materialization

The post-admission payout overlay now accepts the explicit disposal context.
The account runner and replay use it without filtering the full Native inbox
or executing the engine again. Existing callers without that context retain
the strict recipient policy. No production collator or validator is activated.

The reviewed joint pair is prepared once in private accounts. Its actual
coordinator output count then feeds the checked participant LT planner alongside
the custody payout. The common start remains derived from authenticated old
accounts and the complete inbox; each participant has its own output count and
end LT. The bound applies to total outputs, not independently to each emitter.

Other write-set accounts remain allocation/storage participants. Being named
in the write set does not make an account a Native ingress role. Misdirected
imports still belong to the coordinator transaction, with original destination
and envelope preserved in routed InMsg evidence.

The overlay independently decodes serialized account balances, transaction
fees, contiguous output indices, message times and exported value including
remaining forwarding fees. Its value-flow graph includes the host fee-funding
edge once. It rebuilds every AccountBlock and ShardAccount privately and checks
the exact changed set before publishing roots. Exports are derived caches,
not queue-ready envelopes or independently trusted replay claims.

## Verification scope

The fixture runs the full engine runner and replay with one custody payout and
two coordinator bounces. It compares all three outputs against independently
prepared transactions, checks one engine invocation and end LT 24, and checks
that replay regenerates an omitted output cache. An expanded write set updates
a third account that is also the destination of a misdirected import: its
balance stays 1000, its data and transaction chain change, and the coordinator
alone receives the additional 100. The caller's old dictionary remains intact.

Removal controls and restored regression results are recorded in
`measurements/uno-v2-joint-overlay-evidence.json`. These are manual rebuilt
controls, not recurring mutation CI.

## Remaining M1 obligations

Actual Native queue insertion, metadata, actual-source DispatchQueue/FIFO rules,
versioned validation exceptions, source-aware voting error classification and
production activation remain separate work. Return authorization, unexpected
bucket liabilities and a free operating budget are not established merely by
cash conservation in this helper. No numeric policy defaults are installed.

This helper-only unit introduces no voting error category and does not modify
the consensus-judgement source files. It awaits M1 milestone review under
AGENTS.md. M1 is not complete.
