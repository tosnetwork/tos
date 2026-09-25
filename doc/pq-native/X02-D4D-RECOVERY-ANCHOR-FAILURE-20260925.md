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
unaccounted filter. The first correction accepted a header only when paired
with a policy-authorized handled row, but did not require the reverse pairing:
deleting the real header and keeping the handled row was still accepted.
The follow-up requires an exact `protocol=ip`, `kind=flower`, `chain=0`
header and authorized handled row one-to-one at the same pref. Missing,
duplicate or malformed headers and extra classifiers are now rejected.

The initial repair retained lagged recovery samples, but still derived its
target from `max(first_recovery, frozen_anchor)+2`, always slept after the
first recovery sample, and the verifier demanded two recovery samples. The
follow-up fixes the target at frozen H47+2, permits one complete recovery
snapshot, and leaves the 180-second verdict tied to the last raw snapshot's
`completed_ns` minus the last rule-remove command's completed time. H48→H49
and immediate H49 pass focused offline controls; H42→H44 cannot stand in for
H47+2 and times out. A single H49 sample after 180 seconds remains red.

Read-only replay on the retained d4d raw is in
`/datax/tos-x02-d4d-offline-20260925/d4d-replay-final.typescript`. The new parser
verifies each complete snapshot 00–07 (H41/42/43/46/47/47/47/47), while the
old d4d parser rejects the first real flower header at sample 01. Sample 08
remains incomplete and is rejected only for its absent recovery range-header
set; this replay is **not** a successful fault-window verdict. The separate
`old-controls-final.typescript` shows two 2e9 runner failures, the old verifier's
single-recovery rejection, and the real missing-header old false-green/new
red. `three-mutants-final.typescript` contains three unique source changes, each
turning one focused control red. The full X02 offline suite is 78/78 green,
recorded in `x02-78-green-final.typescript`; all four commands exited 0 with
expected embedded red controls. `SHA256SUMS-final` in that evidence directory
(SHA-256 `4c8c265cd69ae37321856cf6452b9d74848106185bdd1e29b525bdb10996725e`)
checks raw outputs, test/replay sources and both Python executable bytes.
The earlier `SHA256SUMS` and non-`-final` logs are preserved as pre-final
development evidence, not silently overwritten.

A new exact committed-tree real run and Mac independent review of this
follow-up are still required. Partial packet loss is separate; X02 remains
OPEN. The d4d run is never relabeled as passing.
