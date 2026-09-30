# C09 supervised functional sampler — review receipt

Candidate only; no user unit installed or enabled. `nhm-c09-functional.timer` and `nhm-c09-functional-stop.timer` both showed `LoadState=not-found`, `ActiveState=inactive` during this review. A dedicated mode-0700 supervision/runtime directory was prepared with frozen script copies, manifest, and private baseline; no sample rows or tokens were copied there. No live grant, QueryService restart, model call, or business-node change was made for this successor.

## Validation

- `/usr/bin/python3` 3.10: 25/25 sampler controls passed, including post-grant append/fsync faults retaining `.inflight`, fresh-process no-grant refusal, exact failed-row review, and real UDS committed-then-503 refusal.
- Disposable Q/M real private-socket run: process query and hourly unknown-consensus/cross-run denial passed; 2 grants, both durably revoked. The harness copied archived M process envelopes read-only into a temporary M with refreshed fixture times and generated independent token files. It does not measure production latency or a soak.
- Stop-receipt offline controls: 4/4 passed, including refusal before the window end or while the timer is active, private one-write output, replaced-Q mismatch recording, same-boot monotonic 72h-plus-tick control, changed-boot refusal, and no sample payload in the receipt.
- `systemd-analyze --user verify` for all five candidate units: exit 0. Runtime `sha256sum --check SCRIPT.sha256`: exit 0; frozen baseline SHA-256 matches the pinned value. Runtime layout is 0700 directory, 0500 scripts, 0400 manifest, 0600 baseline. Active Q-aware stop-v2 targets 2026-10-03 07:10 UTC; old 01:10 stop is inactive and Q-aware sampler remains active. Functional units remain not installed.
- Service pins existing Q binary SHA-256 `e37f9c4353bb80f5ae8acd3a941d7eeb21b5f116a448448adb79588fb94cf8ee` and the private one-shot Q baseline SHA-256 `25c0458888a275bcf9568bc1fc53d914e9d5a3901932b0840444d99a3ea3382f`.

The proposed first successful functional sample cutoff is 2026-09-30 06:55 UTC and proposed stop is 2026-10-03 07:10 UTC. The stop receipt records actual first-pass UTC and boot/BOOTTIME duration; no 72-hour window is claimed before sampling.

## Exact source and candidate units

- `scripts/sample-query-functional.py` SHA-256 `7e5b1d73e7a9d495cf8ab95ef7540e8fdb4cdaf3ed9774aca61b7c113633fad4`
- `scripts/test-sample-query-functional.py` SHA-256 `50a71560437af9a6000737ba3c3d7035540535f9a6cc14b8a8f032f8a37f415a`
- `scripts/write-c09-functional-stop-receipt.py` SHA-256 `8ed8d24d1c5b68222a4251be161f5ef82e5883195affe9a53986b43edfc37267`
- `scripts/test-write-c09-functional-stop-receipt.py` SHA-256 `793f36b3dcb415f3fc1ed3a7fa502fa3133e0a0597a54424a2259302ef694ec3`
- `scripts/test-sample-query-functional-socket.py` SHA-256 `8ee4646b3f84e45127920bd94937a9236bbf209cc735736891a5faafa62c39a1`
- `perf/C09-FUNCTIONAL-SOAK-CONTRACT.md` SHA-256 `76b1f3d3aabc20aae3e4b5ad9583098376066e109a6a1670ded59a11bce258a7`
- `deploy/c09-functional-supervised/nhm-c09-functional-alert.service` SHA-256 `c60f41f8cfb8a0c1443a9def7726938b3560c4cf3f03f7bd0ed14c1bb4994809`
- `deploy/c09-functional-supervised/nhm-c09-functional-stop.service` SHA-256 `7bb12559b1d9648ea8eefc4c57494dc70b76a23faa2f1cc04938028a66384c7f`
- `deploy/c09-functional-supervised/nhm-c09-functional.service` SHA-256 `68a85b348981e4de2f3dc3b513ef3f6107ab9915ba297130fc96497bb6cdb6a9`
- `deploy/c09-functional-supervised/nhm-c09-functional-stop.timer` SHA-256 `b7d076879dad39921caafda7e409721d3ced52fc23ad8a2adb4638fe28e17557`
- `deploy/c09-functional-supervised/nhm-c09-functional.timer` SHA-256 `47cba79a77747dc1523bdb3f9a5f803c233bd521583c924bf467628b05eacdfe`
- `deploy/c09-functional-supervised/SCRIPT.sha256` SHA-256 `3933b324b6ec1a1623f98484003be07fea3eadb45dc838f083b5c0f30fa1d52a`
- `deploy/c09-functional-supervised/README.md` SHA-256 `c4102c5bec842d48445823741e199fcf79dae91d34c6b7fc363b042e249993ef`

## Raw output retained locally

The raw output is kept in this same mode-0700 directory, 0600 per file, Git-ignored. It contains no token values or process payload. These hashes bind the review result to exact local bytes:

- `offline-tests.raw.log`: 124 bytes; SHA-256 `3cc2ee461bc2216d0d6fd39ed1a902a21b9cfa07b85db065a3f26e3cf0cb5bb9`
- `isolated-socket.raw.json`: 663 bytes; SHA-256 `19e1be14f6ccc8a16ff3699b76123509c21dd2d8e82c9845769de61a4839ecc0`
- `units-verify.raw.log`: 0 bytes; SHA-256 `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`
- `source-check.raw.log`: 194 bytes; SHA-256 `e08b598e70f52bf4191513270faf8f501f714be897ebebc9e72854ae189526fb`
- `stop-receipt-tests.raw.log`: 103 bytes; SHA-256 `c1dffb70dba98c39f6d3160dd8d69611f73e43edb30cec9880171bd2fc48adf8`
- `runtime-layout.raw.log`: 475 bytes; SHA-256 `f6fb47d86d6bd928da1d4625f749d828576379823abfc59f25b9b9cb54c4956e`

- `q-timer-alignment.raw.log`: 448 bytes; SHA-256 `8da73fa59287399fad630f25d68d8338b595c56dd604b8fef412d888b5387c5a`

Independent source review and owner-controlled installation/enablement remain required. This receipt does not claim C09 or the 72-hour gate.
