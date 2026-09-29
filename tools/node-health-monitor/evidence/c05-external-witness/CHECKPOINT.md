# C05 development checkpoint — not acceptance

Baseline `node-health-monitor@88d5d95ad98413e035c4fec04a68c6306b5bb26d`.
All test inputs are synthetic or isolated loopback TLS. No business node, key,
live chain source, production deployment or main merge was used.

Implemented so far: closed bounded plan/source DTO, semantic source and exact
transport digests, plan-content binding, typed block/consensus reported-anchor
comparison, conservative original-row age and clock quality, O fixed cache-only
polling and 15-second no-catch-up schedule, explicit development-only watchdog
wiring with supervised lane lifetime and O heartbeat/notice status, M fixed
cache collector with identity-bound archive ACK, separate durable historical
archive namespace/quota/dedup/quarantine. Historical archive creates no rule fact.

Restored `CARGO_BUILD_JOBS=2 scripts/run-contract-tests.sh` naturally exited 0:
`raw/closure-first.log` SHA-256
`4fe51d63c8472000e0f9ab1fdd8c3a37d6bd2bfc130f86e66d835c856fe55901`.
It includes 23 closed schemas, six actual success handlers, 11 production
doctor refusals and the full Rust workspace suite. One native producer-pair test
is marked ignored because the external C++ pair input was not supplied; this is
not counted as a C05 pass. The file is a checkpoint, not a final frozen index.

Targeted child-task permit mutation changed `let _slot = slot;` to
`drop(slot);` in `health-services/src/witness.rs`, then restored it. Baseline
`raw/child-lifetime-baseline.log` SHA-256
`d7ac4d21e34ebad73133737f1fb4ddec9d9603268d59a902fbb6e641aec94965`
exited 0; compiled mutant `raw/child-lifetime-mutant.log` SHA-256
`18c1199dffdd0dd0dc9c27777f3d9594b420e2d57c45965246958fe015a442aa`
exited 101 at active-request in-flight `0 != 4`; restored
`raw/child-lifetime-restored.log` SHA-256
`b30e6cfc33e08483d377094a2e0c6cac512dfc9b2ab1986a11d8944d1ef88df4`
exited 0. This red establishes active-child permit retention, not a separate
deterministic post-cancel destruction barrier. The mutated full-source SHA was
not frozen before restoration, so this mutation is provisional evidence only.
Early narrower DTO/cache logs and the supervisor's preserved historical red
reviews are lineage, not final-source passes.

Open C05 gates: no approved production cache endpoint, source work/egress
measurement, timeout-quarantine persistence and operator activation across O
restart, qualified current M/A witness rule input with measured collector/M
transport and queue elapsed, or deterministic verified-proof adapter. Current
`observer_disagreement` rule remains pending; reported quorum/validity and
missing private votes cannot mint node faults. O heartbeat route exists, but
the external independent receiver and production self-health deployment are
not configured or tested. This checkpoint does not authorize production.

After this checkpoint, the isolated O subprocess and an in-tick lane-exit
changed-property test were added; see `RUNTIME-SUPERVISION-RECEIPT.md` for
exact raw logs and source/binary identities. Historical `witness_archive_v1`
now has a **separate** bounded current-source activation/high-water/quarantine
state and direct development age/order review; see
`CURRENT-M-INTERFACE-PROPOSAL.md` and `CURRENT-M-SLICE-RECEIPT.md`. The actual
archive route invokes that review only with unknown transport age and emits no
rule fact. M still lacks measured collector-to-M transit, queue, commit and
post-read elapsed for a usable current view, and the collector exposes only
its historical ACK to M. No archive ACK, stored body, or O cache read should
be interpreted as an activated current witness rule fact. This is the precise
remaining C05 development mismatch, not a reason to fabricate a production
adapter.
