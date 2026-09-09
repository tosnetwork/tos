Private production-method call-site evidence

The harness calls ValidateQuery::check_mc_state_extra and observes its final typed result. It seeds authenticated-predecessor and candidate slots; it does not establish complete predecessor authentication, full-block validation, collator reachability, or D40 acceptance.

- Removing the complete delta comparison: only the unauthorized wc=3 insertion changes from CandidateReject to CandidateAccept, tripping 931; unchanged remains accepted.
- Treating candidate delta mismatch as a local fault: only 931 fails, with final typed local failure.
- Treating a malformed authenticated-predecessor ledger as a candidate fault: only 932 fails, with final typed CandidateReject.

Every control has a successful mutant build, exact source restoration and reconstructed mutation hash, explicit target rebuilds, and passing restored cases. Each report pins its own source commit; the earlier two-case comparison control predates the additional local-fault case. The generated fixture has no Counter descriptor or activation capability.

The initial unchanged/corrupt logs under fixture record missing diagnostic parent directories before the validator ran. They are dependency failures, not guard evidence. Later control runs create their diagnostic parent directories. Generation used SOURCE_DATE_EPOCH=1788973200, crypto/create-state and crypto/test/workchain-instance-callsite-genesis.fif from the pinned source. Native Cell hash and BoC file hash are distinct inputs.
