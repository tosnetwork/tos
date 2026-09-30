# C09 supervised functional sampler — review receipt

Candidate only; no user unit installed or enabled. `nhm-c09-functional.timer` and `nhm-c09-functional-stop.timer` both showed `LoadState=not-found`, `ActiveState=inactive` during this review. No live grant, QueryService restart, model call, or business-node change was made for this successor.

## Validation

- `/usr/bin/python3` 3.10: 21/21 offline controls passed, including failed-sample latch, unconfirmed cleanup, orphaned inflight marker, exact one-row operator acknowledgement, stale-ack refusal, and real UDS committed-then-503 followed by a no-grant tick.
- Disposable Q/M real private-socket run: process query and hourly unknown-consensus/cross-run denial passed; 2 grants, both durably revoked. The harness copied archived M process envelopes read-only into a temporary M with refreshed fixture times and generated independent token files. It does not measure production latency or a soak.
- `systemd-analyze --user verify` for all five candidate units: exit 0. `sha256sum --check SCRIPT.sha256`: exit 0.
- Service pins existing Q binary SHA-256 `e37f9c4353bb80f5ae8acd3a941d7eeb21b5f116a448448adb79588fb94cf8ee` and the private one-shot Q baseline SHA-256 `25c0458888a275bcf9568bc1fc53d914e9d5a3901932b0840444d99a3ea3382f`.

## Exact source and candidate units

- `scripts/sample-query-functional.py` SHA-256 `c1119c4d1d367c980295b812eb3a9eaf66f6f1577a679341f6be83e457536111`
- `scripts/test-sample-query-functional.py` SHA-256 `3788088a706145734d6cc35f5ee82cc31485c33ff5bf55d333a35aadfd1fef17`
- `scripts/test-sample-query-functional-socket.py` SHA-256 `8ee4646b3f84e45127920bd94937a9236bbf209cc735736891a5faafa62c39a1`
- `perf/C09-FUNCTIONAL-SOAK-CONTRACT.md` SHA-256 `1067de7a80bcc99be9a8160e7ed09d90d88e6710f23a65751bcbecc7997436fe`
- `deploy/c09-functional-supervised/nhm-c09-functional-alert.service` SHA-256 `c60f41f8cfb8a0c1443a9def7726938b3560c4cf3f03f7bd0ed14c1bb4994809`
- `deploy/c09-functional-supervised/nhm-c09-functional-stop.service` SHA-256 `89a681a378b4b622b194fc92398e0d7a8278d7561a1b403fba81f379e48dfb77`
- `deploy/c09-functional-supervised/nhm-c09-functional.service` SHA-256 `29e48de5e5fee354eddbc4b51328c64a5486c29b8bdaca5bbc2db25a4f8df984`
- `deploy/c09-functional-supervised/nhm-c09-functional-stop.timer` SHA-256 `d265a034c0e891a8d2f2878ea70102b1d610308a10973fa4b4cb997fb0740b6b`
- `deploy/c09-functional-supervised/nhm-c09-functional.timer` SHA-256 `47cba79a77747dc1523bdb3f9a5f803c233bd521583c924bf467628b05eacdfe`
- `deploy/c09-functional-supervised/SCRIPT.sha256` SHA-256 `15bb19dd383463e064b04c693191b5db497fb608fa5e5edaecbcfb559eb212b1`
- `deploy/c09-functional-supervised/README.md` SHA-256 `457a613dc63426440570da912b703f34c13107d0e30d823195177eed087f0ad8`

## Raw output retained locally

The raw output is kept in this same mode-0700 directory, 0600 per file, Git-ignored. It contains no token values or process payload. These hashes bind the review result to exact local bytes:

- `offline-tests.raw.log`: 120 bytes; SHA-256 `f5c095efc7d564611fb89f3424a3322ba337e0e25fa916701822f6291cbca36e`
- `isolated-socket.raw.json`: 663 bytes; SHA-256 `099d9d73a29898157289252fb40b4a4f4f42272629f1d436f16dad9951f0b0bf`
- `units-verify.raw.log`: 0 bytes; SHA-256 `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`
- `source-check.raw.log`: 112 bytes; SHA-256 `474c455178ff7404ae8a8987f3b147fe3f279dfbc6c92658b11757a08147cb15`

Independent source review and owner-controlled installation/enablement remain required. This receipt does not claim C09 or the 72-hour gate.
