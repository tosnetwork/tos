# C09 local query-only anchor rollout

At `2026-09-30` UTC, only `nhm-local-query.service` was updated from the
`14bb30d0` binary SHA-256
`ff7c11e51edbb2a3d4f9633aff8298587c7dda8dc2a2b4bb9b6e0f2ff9a0bc5e`
to branch HEAD `31fc2f615ec3325d0e6bfe69f37f692068786bc0`, binary SHA-256
`e37f9c4353bb80f5ae8acd3a941d7eeb21b5f116a448448adb79588fb94cf8ee`.
The private, complete backup and rollback receipt is
`/home/tomi/nhm-supervision/c09-local/query-anchor-update-20260930T003210Z/QUERY-ANCHOR-DEPLOYMENT.md`.

Before replacing the binary, a consistent backup of the live Q ledger passed
SQLite `integrity_check=ok`. A disposable Q copy advanced from global M
watermark/anchor `18271/18269` to `18277/18277`; after cleanup of the private
one-off trial sockets, the same disposable Q reopened with `/healthz` 200.
The live restart changed only QueryService PID `3645080` to `3847778`.
M, all six supervised collectors and the six business nodes retained their
preflight PIDs. Both private sockets remained mode `0600`.

The authenticated, read-only projection-health route returned HTTP 200 with
`lagging`, matching source identity, `manager_conflicted=false`, and a
3-sequence M/Q lag at the sampled instant. This is a measured lag, not a
continuous catch-up claim. The deployment manifest binds the current query
binary/source and has SHA-256
`654b940fd569c3cc1979e1736c34028186041bde0f50830379004ab0fd1c867a`.

Pinned AURA `1000f119d` read six real `partial` process payloads through the
running broker, matched each to its retained M parent and node PID, confirmed
consensus remained unknown and cross-run access was denied, and revoked both
fixed grants. Test exit 0; private raw log SHA-256
`dc92dd40135fc4caaf81465e99cabf4a2d92db47c63c74ac32911b03a1865505`.
No model provider was called.

The existing one-minute sampler first included a read-only Q projection probe
at `2026-09-30T00:38:14Z`; its first row showed six fresh M process sources,
no sample errors and Q status `lagging` by 16 global M sequences. A manual
sample then measured lag 3; the next timer row was `caught_up` with lag 0.
Its 153 prior rows were M/unit-only and cannot count toward Q-aware continuity. The sampler
does not repeatedly exercise AURA grants or tool calls. Concurrent broker
latency, failure and resource profiles, retention, rollback drill and 72-hour
continuity remain unaccepted. This local rollout is not production health or
C09 acceptance.
