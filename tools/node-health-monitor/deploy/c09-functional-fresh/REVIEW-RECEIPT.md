# C09 fresh functional window source review receipt

Candidate branch: `nhm/c09-functional-fresh-window-starbridge`. This is a source and disposable-control receipt, not a live 72-hour measurement or authorization to install units. The original 03:00 failure log and `.inflight` marker remain untouched. No new manual-resolution receipt, v2 runtime directory, v2 unit, timer, Q/M service, business node, or model call was created in the live environment.

| Boundary | Exact source SHA-256 | Exercising control |
| --- | --- | --- |
| Window binding, latch, unknown POST accounting | `sample-query-functional.py` `bcc61402af10edf6bbfccdbec72f9549febd56cb5b30b2e1b8658db114c7bd9c` | Functional offline tests and disposable Q/M socket |
| Private resolution and new Q baseline | `prepare-c09-fresh-window.py` `b718cc609ffd5f43a3b7fecc2245acac0ff0467da6e307634c99c1f134e4993e` | Resolution, replacement, unresolved-grant negatives |
| Stop receipt and continuity | `write-c09-functional-stop-receipt.py` `ba543dcbe184c7d55f3c8cf8710a2ca7da0f9ad4ef8a775505ad8924b3c462a3` | Stop/identity/marker/slot/error/elapsed negatives |

`python3 -m unittest test-prepare-c09-fresh-window.py test-write-c09-functional-stop-receipt.py test-sample-query-functional.py` (with repository script paths): 36 tests, exit 0. `test-sample-query-functional-socket.py`: disposable Q/M, two authorized grants durably revoked, fixed process query and both hourly negative controls passed, exit 0. No production Q or M write occurred. Rendered all five v2 unit templates with synthetic values in a temporary directory and ran `systemd-analyze verify`: exit 0; unrelated host warnings about netplan permission and snapd `RestartMode` appeared. `git diff --check`: exit 0.

Sensitivity control: copied the stop writer and tests into a temporary directory. Baseline stop tests exit 0; deleted `all_rows_pass` from the 72-hour gate; mutant exits 1 with failures on the inserted primary-error row and duplicate/rollback slots; restored source exits 0. This proves those tests reach the gate. Synthetic elapsed rows are test fixtures and provide no soak evidence.

Installation remains blocked on a same-Q manual resolution receipt, preparation of the new private baseline/window anchor, review of the rendered dates and source checksum manifest, full Q-aware interval alignment, and owner-controlled enablement. The stop receipt deliberately records `acceptance_claim=false` even when its elapsed predicate holds.
