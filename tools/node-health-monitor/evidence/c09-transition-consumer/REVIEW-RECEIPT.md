# C09 transition consumer — isolated review receipt

Future coordinated Q upgrade candidate only. No running Q binary, frozen functional script, runtime manifest, timer, live grant, or service was changed by this branch. Current runtime consumer SHA-256 remains `7e5b1d73e7a9d495cf8ab95ef7540e8fdb4cdaf3ed9774aca61b7c113633fad4`; the candidate source hash below differs deliberately. The existing manifest still pins the runtime source and would reject an unreviewed candidate copy.

Lighthouse producer: `nhm/c09-anchor-integration@4050107cc`, `observability.rs` SHA-256 `8a2f5f08d4e0945dde8078c05b077f6fabf8f5be8ea7ffb63e9e84113677e3bc`. Its `transition` envelope is HTTP 503/schema 1 and a 503 is never `caught_up`.

Validation: 26/26 offline controls passed, including valid 503 transition as an explicit unavailable/failure status, invalid HTTP/field cases, false-caught-up rejection, and run-level separation of fixed-grant query success from unavailable projection head. Disposable Q/M private-socket regression passed with two grants durably revoked; that harness uses the current production Q binary and does **not** inject the new producer transition race. Real-handler overlap remains a coordinated upgrade gate.

## Exact candidate bytes

- `scripts/sample-query-functional.py` SHA-256 `4412257d599b4dc0ff1e861cb3b69258a8912caf12ace0dfa353a43214d4ab5b`
- `scripts/test-sample-query-functional.py` SHA-256 `b0f39f86fc686e7368cbb6bd069c90839bfaba414d7140cd63627fc7162d604d`
- `scripts/test-sample-query-functional-socket.py` SHA-256 `4fab9eea41385a2fd35118bd6735d3c8f861e10feb2d8aad3b3f16e8752d4f1b`
- `perf/C09-TRANSITION-CONSUMER-CONTRACT.md` SHA-256 `af908316601e9ad978d297c8d512c826fdc30c0014222b45efd8595d69151957`

## Raw local controls

Raw output is Git-ignored under this mode-0700 directory; it contains no token or process payload.

- `offline-tests.raw.log`: 125 bytes; SHA-256 `09b92915140ce27be53d96a895ebcf4c5a9ed698972b5f80b549454f79fdd297`
- `isolated-socket.raw.json`: 663 bytes; SHA-256 `0f9cdd7d2ccde98bb835e79df689697b9e14b33826287060e96559322fce8f14`

No 72-hour or C09 acceptance claim is made. A Q deployment requires exact consumer/producer review, runtime SHA pinning, a real private HTTP overlap control, and a decision about restarting the functional/Q-aware window.
