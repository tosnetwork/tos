# Election registration retention and fee runway

The runner and manual stake command derive a pending registration deadline from
`max(original election id, now + elections_end_before) + validators_elected_for + 300`.
This covers a delayed election without changing its original identity. The runner
also reconciles existing ADNL associations with the actual current/next validator
sets before the closed/finished-elector early returns. Registrations are extended
to the actual duty end plus300 seconds. A current set retained beyond its planned
end is kept registered through the delay. An unrelated address is never attached,
no deadline is shortened, and neither renewal generates/signs a new key/message.

The control operations are ordered permanent record then existing ADNL association.
A partial failure is surfaced; the same idempotent calls can reconcile while
the original address remains known. Already-deleted addresses require evidence-based recovery.
Completed renewals update the local snapshot before another action can reuse it.
All addresses sharing a permanent key use its longest duty deadline. A failed node skips its own value operations and exposes the error; healthy nodes
continue pool maintenance, recovery and participation even if the failed node
was excluded from future elections. An
existing key export failure is an error, never evidence that the key is absent.
An already-deleted ADNL association is refused with an explicit reconciliation
message; an address is not guessed from unrelated global ADNL entries. Retention
prevents expiry during normal polling; a previously broken legacy record still
needs evidence-based operator recovery. Validator engines and signing ledgers are
not restarted or rewritten by this change.

Every successful runner tick, including closed elections, reads the operator fee
wallet. Below5.2TOS (three1.4TOS stake submissions plus1TOS reserve), it logs
`ELECTION_FEE_RUNWAY_LOW` and exposes that warning through the existing node
`last_error` snapshot. A failed balance read logs/exposes
`ELECTION_FEE_BALANCE_UNAVAILABLE`. These are advisory reserves, not a guarantee
of three future terms: recovery, maintenance, price changes and retransmission
can cost more. There is no automatic top-up, coordinator authorization, message
send, or external notification. Existing send-time affordability checks remain.

Registration planning has at most128 records and16 addresses per record; the
result is at most2048 bounded renewal entries, discarded after a tick. No cache,
background task, database, key material or growing history is introduced. Control
expiry/election timestamps must fit the signed32-bit wire format; arithmetic is
checked. The operator's existing tick interval bounds warning frequency. The
current/next configuration reads retain their existing transport trust boundary;
this change affects local metadata availability, not consensus validity.

Reproduce with `cargo +1.97.1 test --manifest-path tosctl/src/Cargo.toml -p elections --release --locked`.
The focused cases cover a late election, actual announced/expired duties, unrelated
and already-retained addresses, non-shortening, malformed/bounded input, exact fee
warning threshold, a closed-elector runner warning, failed balance/export reads,
and metadata renewal with a closed elector and no send/key generation.

Native retirement is a separate policy: after a new set is installed, the engine
may retire transport records whose original election identity precedes the new
term, even when their expiry is later. That inherited policy is unchanged. On a
post-quantum network these records are operator bookkeeping, not the custodied
consensus identity: owned PQ ADNL membership is derived separately from the
current/next/previous chain sets and configured addresses. Renewal keeps pending
and still-present records usable; it does not promise to recreate retired keys
or retain every legacy transport record through the entire rebased term. The
actual current PQ certificates remain the operational authority.

A failed full validator-configuration read is also unknown. The runner preserves
the previous metadata for diagnostics, flags that node unavailable and skips its
value operations. An empty successful configuration remains distinguishable from
a failed read; neither a cold start nor a cached record is turned into permission
to generate keys after a read failure. Other nodes continue independently.
