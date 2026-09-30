# C09 supervised functional sampler — review receipt

Candidate only; no user unit installed or enabled. `nhm-c09-functional.timer` and `nhm-c09-functional-stop.timer` both showed `LoadState=not-found`, `ActiveState=inactive` during this review. A dedicated mode-0700 supervision/runtime directory was prepared with frozen script copies, manifest, and private baseline; no sample rows or tokens were copied there. No live grant, QueryService restart, model call, or business-node change was made for this successor.

## Validation

- `/usr/bin/python3` 3.10: 24/24 sampler controls passed, including post-grant append/fsync faults retaining `.inflight`, fresh-process no-grant refusal, exact failed-row review, and real UDS committed-then-503 refusal.
- Disposable Q/M real private-socket run: process query and hourly unknown-consensus/cross-run denial passed; 2 grants, both durably revoked. The harness copied archived M process envelopes read-only into a temporary M with refreshed fixture times and generated independent token files. It does not measure production latency or a soak.
- Stop-receipt offline controls: 3/3 passed, including refusal before the window end or while the timer is active, private one-write output, replaced-Q mismatch recording, and no sample payload in the receipt.
- `systemd-analyze --user verify` for all five candidate units: exit 0. Runtime `sha256sum --check SCRIPT.sha256`: exit 0; frozen baseline SHA-256 matches the pinned value. Runtime layout is 0700 directory, 0500 scripts, 0400 manifest, 0600 baseline.
- Service pins existing Q binary SHA-256 `e37f9c4353bb80f5ae8acd3a941d7eeb21b5f116a448448adb79588fb94cf8ee` and the private one-shot Q baseline SHA-256 `25c0458888a275bcf9568bc1fc53d914e9d5a3901932b0840444d99a3ea3382f`.

## Exact source and candidate units

- `scripts/sample-query-functional.py` SHA-256 `9bd72cb805a660442049791a3deeebe933f395f0c767c422624d699f85ebc1e3`
- `scripts/test-sample-query-functional.py` SHA-256 `8694133096660aa1a0dfbdb27aeb5910fd1ca3683425607182b0a747cad6eef0`
- `scripts/write-c09-functional-stop-receipt.py` SHA-256 `2ea2eb0b7b5b7233ea6628ccd3c211e908f82945606729b3f97f0613de3f16d7`
- `scripts/test-write-c09-functional-stop-receipt.py` SHA-256 `6ad848435caa72b5ba6bcf4d01d0d7f216f39bee19f8d09f91224d277429d85d`
- `scripts/test-sample-query-functional-socket.py` SHA-256 `8ee4646b3f84e45127920bd94937a9236bbf209cc735736891a5faafa62c39a1`
- `perf/C09-FUNCTIONAL-SOAK-CONTRACT.md` SHA-256 `2be4fc16cd0a28882555711a30dd29cac5da185bcd3b4c613ce4f212b17418ad`
- `deploy/c09-functional-supervised/nhm-c09-functional-alert.service` SHA-256 `c60f41f8cfb8a0c1443a9def7726938b3560c4cf3f03f7bd0ed14c1bb4994809`
- `deploy/c09-functional-supervised/nhm-c09-functional-stop.service` SHA-256 `371ff733c9e1fb73475c93b8ab257d4e3edcf3833adb34475960a79edb4956ad`
- `deploy/c09-functional-supervised/nhm-c09-functional.service` SHA-256 `301fe3eba5ed15adf738203dffc84ec77a60942c3a287862ea597e4f22401514`
- `deploy/c09-functional-supervised/nhm-c09-functional-stop.timer` SHA-256 `d265a034c0e891a8d2f2878ea70102b1d610308a10973fa4b4cb997fb0740b6b`
- `deploy/c09-functional-supervised/nhm-c09-functional.timer` SHA-256 `47cba79a77747dc1523bdb3f9a5f803c233bd521583c924bf467628b05eacdfe`
- `deploy/c09-functional-supervised/SCRIPT.sha256` SHA-256 `8666e6a036d47a1f42f3e52eefe996bddfc95f736f840ab0be458a2e17e881f1`
- `deploy/c09-functional-supervised/README.md` SHA-256 `734a92fd8c110634d3053ce0386f28d02c6374577b213ca185ede0bc157940ca`

## Raw output retained locally

The raw output is kept in this same mode-0700 directory, 0600 per file, Git-ignored. It contains no token values or process payload. These hashes bind the review result to exact local bytes:

- `offline-tests.raw.log`: 123 bytes; SHA-256 `99c72d5de94f9e65f16999496820677e72e0afab86263f983720e9a6ab78f6f2`
- `isolated-socket.raw.json`: 663 bytes; SHA-256 `d81748fa1e5f96e4c2faa895daf19222fc48bd8ba304357e9f1535716e332fe5`
- `units-verify.raw.log`: 0 bytes; SHA-256 `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`
- `source-check.raw.log`: 194 bytes; SHA-256 `e08b598e70f52bf4191513270faf8f501f714be897ebebc9e72854ae189526fb`
- `stop-receipt-tests.raw.log`: 101 bytes; SHA-256 `41cee9cc70f8e2902ff4277cf9577cbdf05c130cf7652490990fd48efa2e4859`
- `runtime-layout.raw.log`: 475 bytes; SHA-256 `f6fb47d86d6bd928da1d4625f749d828576379823abfc59f25b9b9cb54c4956e`

Independent source review and owner-controlled installation/enablement remain required. This receipt does not claim C09 or the 72-hour gate.
