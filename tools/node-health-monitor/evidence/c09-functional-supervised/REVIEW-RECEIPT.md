# C09 supervised functional sampler — review receipt

Candidate only; no user unit installed or enabled. `nhm-c09-functional.timer` and `nhm-c09-functional-stop.timer` both showed `LoadState=not-found`, `ActiveState=inactive` during this review. No live grant, QueryService restart, model call, or business-node change was made for this successor.

## Validation

- `/usr/bin/python3` 3.10: 24/24 offline controls passed, including failed-sample latch, failed journal append followed by a fresh-process no-grant refusal; post-grant append and fsync failures preserve the marker, unconfirmed cleanup, orphaned inflight marker, failed-row/highwater operator acknowledgement and receipt-inert orphan marker, stale-ack refusal, and real UDS committed-then-503 followed by a no-grant tick.
- Disposable Q/M real private-socket run: process query and hourly unknown-consensus/cross-run denial passed; 2 grants, both durably revoked. The harness copied archived M process envelopes read-only into a temporary M with refreshed fixture times and generated independent token files. It does not measure production latency or a soak.
- `systemd-analyze --user verify` for all five candidate units: exit 0. `sha256sum --check SCRIPT.sha256`: exit 0.
- Service pins existing Q binary SHA-256 `e37f9c4353bb80f5ae8acd3a941d7eeb21b5f116a448448adb79588fb94cf8ee` and the private one-shot Q baseline SHA-256 `25c0458888a275bcf9568bc1fc53d914e9d5a3901932b0840444d99a3ea3382f`.

## Exact source and candidate units

- `scripts/sample-query-functional.py` SHA-256 `9bd72cb805a660442049791a3deeebe933f395f0c767c422624d699f85ebc1e3`
- `scripts/test-sample-query-functional.py` SHA-256 `8694133096660aa1a0dfbdb27aeb5910fd1ca3683425607182b0a747cad6eef0`
- `scripts/test-sample-query-functional-socket.py` SHA-256 `8ee4646b3f84e45127920bd94937a9236bbf209cc735736891a5faafa62c39a1`
- `perf/C09-FUNCTIONAL-SOAK-CONTRACT.md` SHA-256 `f70e8907ff7551e7b17582616521faded04eb7d6fc94a808d3b418c7c34e3b7f`
- `deploy/c09-functional-supervised/nhm-c09-functional-alert.service` SHA-256 `c60f41f8cfb8a0c1443a9def7726938b3560c4cf3f03f7bd0ed14c1bb4994809`
- `deploy/c09-functional-supervised/nhm-c09-functional-stop.service` SHA-256 `89a681a378b4b622b194fc92398e0d7a8278d7561a1b403fba81f379e48dfb77`
- `deploy/c09-functional-supervised/nhm-c09-functional.service` SHA-256 `29e48de5e5fee354eddbc4b51328c64a5486c29b8bdaca5bbc2db25a4f8df984`
- `deploy/c09-functional-supervised/nhm-c09-functional-stop.timer` SHA-256 `d265a034c0e891a8d2f2878ea70102b1d610308a10973fa4b4cb997fb0740b6b`
- `deploy/c09-functional-supervised/nhm-c09-functional.timer` SHA-256 `47cba79a77747dc1523bdb3f9a5f803c233bd521583c924bf467628b05eacdfe`
- `deploy/c09-functional-supervised/SCRIPT.sha256` SHA-256 `e36afbb706904b193deb46b1d9ee1833c72c78bf1d5154adb7e8c86a233317fa`
- `deploy/c09-functional-supervised/README.md` SHA-256 `ae83af2b1e7cef3ee4319c8b89247378699930415cb251b88d286e9b1c8778ab`

## Raw output retained locally

The raw output is kept in this same mode-0700 directory, 0600 per file, Git-ignored. It contains no token values or process payload. These hashes bind the review result to exact local bytes:

- `offline-tests.raw.log`: 123 bytes; SHA-256 `99c72d5de94f9e65f16999496820677e72e0afab86263f983720e9a6ab78f6f2`
- `isolated-socket.raw.json`: 663 bytes; SHA-256 `d81748fa1e5f96e4c2faa895daf19222fc48bd8ba304357e9f1535716e332fe5`
- `units-verify.raw.log`: 0 bytes; SHA-256 `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`
- `source-check.raw.log`: 65 bytes; SHA-256 `e5d872f8b382dba62f3da9ebaaaf1a347292548241495dfb5e636a4ffb5f59c5`

Independent source review and owner-controlled installation/enablement remain required. This receipt does not claim C09 or the 72-hour gate.
