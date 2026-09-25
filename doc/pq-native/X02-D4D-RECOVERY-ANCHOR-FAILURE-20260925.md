# X02 d4d directed run: premature recovery-anchor rejection

The clean committed tree `d4d12eb749843ab618c3784689a3b0a6501a8a75`
started one four-validator Stage A network at 2026-09-25 21:45:04 UTC:
`test/integration/.x02-stage-a-d4d12eb74-20260925/20260925T214504Z/`.
Its readiness SHA-256 is
`6553a24a3fca0d62058b94499950ed91d3898529409d6004567487083405b47a`;
the pre-fault policy SHA-256 is
`86be6a2e28dfd43818153c7fa8b532d4e1a9bda16cdce96c499d1d81f76f50c8`.
Four distinct validator PIDs owned both ADNL UDP 26602/05/08/11 and QUIC UDP
27602/05/08/11; the pre-cut `ss -uapn` raw SHA-256 is
`4f2b2c142cf39dc5625f116c51ed13d05b15ebc678807b643423c53ddbfcd136`.
The supervisor's cut-time dual-UDP pcap spans 21:50:51–21:52:51 UTC:
`/datax/n6-supervisor-x02-d4d-evidence/dual-udp-on-cut.pcap`
(SHA-256 `e79898c7cdc7400b6ca43d7324075b9979cf0d9dc9a3e14c073ffd22d9030f4e`).
An isolated Ubuntu24 Z01 compile overlapped only the earlier Stage A startup
21:45:03–21:46:37 UTC, before readiness or tc installation; it is a timing
provenance limitation, not silently omitted.

The directed runner exited 1. Its 54-file SHA index is
`test/integration/.x02-stage-a-d4d12eb74-20260925/20260925T214504Z/x02-directed-SHA256SUMS`
(SHA-256 `3749378cb2dce94f1273b5df75bac7d78eee60f5ecdb4d731f5c85c61bf1733b`).
`result.json` SHA-256 is
`0a6dd19ea8ddb441a1d57712a19ad27c7d6a3b70d046c44c9749898713bb268b`.
All 20 exact ADNL+QUIC rules installed and each showed positive drop counts;
20 typed `flower` removals exited 0. `cleanup.json` SHA-256 is
`0296b73923b6129fdb50a4d06d979dbbeee01c0a3899f19a68d5976775bf47a9`;
`lo` returned to root `noqueue` with no egress filters.

The enclosing Stage A run ended naturally at 22:05:41 UTC with separate
`RuntimeError: validator experiment ended with 8 outstanding allocations`,
exit 1. Its console SHA-256 is
`c95d64faf50b4b6a9c6a6bb22d43f01aa8e4190638fdb6f7866ccfea3e9019d0`;
report SHA-256 is
`24133363c7963fa3539ea4cb060b7a56239997d41866c4444f43ed9512fdd098`.
All validator/runner processes exited and `lo` remained `noqueue` with no
egress filters. Stage A reward settlement and X02 fault-window verdict are
separate: neither failure is silently relabeled as a chain safety result.

Raw common heights were baseline H41, 3/4 H42/H43/H46, then four 2/4
samples all H47 after the frozen 30-second drain. The first recovery raw
sample (`sample-08-recovery.json`, SHA-256
`bbe5b0013725d59aa1555d705add45537d2155f223b7d54d3eab61e488902d99`)
contains HTTP 200 tips node1/2/3 H47 and node4 H42, with four-node common
H42. Fixed `capture()` incorrectly required that first four-node common
immediately equal or exceed the *two-live-node* H47 anchor, and wrote
`capture_error=ValueError('common height regressed below anchor')` before
the 180-second catch-up window could be observed. This is an evidence-harness
failure, not a demonstrated chain recovery failure or an X02 PASS.

The same immutable `tc -j -s filter` bytes expose another independent
verifier issue: each real flower appears as a no-handle header row immediately
followed by its handled action row. For `event-01-r1-install.json`, raw stdout
SHA-256 is `425146c59487044cb9a889d930192a00de7e6cbf6b76f464afd44de2d3fd6588`.
The d4d `validate_tc_surface()` rejected the authorized header as an
unaccounted filter. The correction accepts only an exact `protocol=ip`,
`kind=flower`, `chain=0` header paired with precisely one policy-authorized
handled row at the same pref; missing/duplicate/malformed headers and extra
classifiers remain red. In a read-only replay of the d4d raw through the
corrected parser, samples 00–07 pass and verification next stops at the
already-retained incomplete sample 08, never a successful verdict.

The isolated repair retains lagged recovery samples and makes the runner wait
for four-node common >= frozen H47 + 2, rather than +2 from first H42. Both
old-source capture rejection and old-runner premature-stop controls turn red;
the corrected targeted suite is green. A new exact committed-tree real run
and independent review are still required. Partial packet loss is separate;
X02 remains OPEN.
