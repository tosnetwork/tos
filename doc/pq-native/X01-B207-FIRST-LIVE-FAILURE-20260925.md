# X01 b207 first live run: process-generation checker failure

X01 remains OPEN. The exact committed source was `b20783d50bfb8666d85f47e999ddf3f246d5c978`. The single four-validator run used:

```
script -q -e -f -c 'PYTHONPATH=test/tostester/src uv run python -u scripts/validator-election-stage-a.py --mode launch-gate --stage a --f01-extended-election-window --build-dir build --output-root test/integration/.x01-stage-a-b20783d50-20260925' test/integration/.x01-stage-a-b20783d50-20260925-console.typescript
```

`launch-gate` sets `pq_full=true` in this harness. The run actually froze an X01 policy before the 3/4 stop and saved X01 stop/start, per-node RPC and trace artifacts. It exited **1** at 18:12:59 UTC with `ValueError: X01 stopped process differs from pre-fault PID identity` from `validate_x01_window`; it did not produce a successful X01 verdict. All validator processes exited. This is a checker-generation mismatch, not evidence of a consensus safety failure.

The run root is `test/integration/.x01-stage-a-b20783d50-20260925/20260925T174726Z`. Except for the console, paths below are relative to that run root; no artifact was moved or rewritten.

| Artifact | SHA-256 |
| --- | --- |
| `test/integration/.x01-stage-a-b20783d50-20260925-console.typescript` | `dffec63a40af1aebfad7180b51f05e8468a9d668794ddc6ee18742d6c9d7008d` |
| `report.json` | `329f4327f81322ae6b60a94950bee908067f637832f79948d8a299ff193636d0` |
| `artifacts/x01-fault-window/policy.json` | `57d7325c3d4d66366c2927617e444584ca58c34c09c50bc77d9f42c21326e3de` |
| `artifacts/x01-fault-window/trace.json` | `895e4dcec025ba4a870c5d49003a16f6769529cedb7a2020956162312da14ee5` |
| `artifacts/f01-finality/capture-manifest.json` | `80de5cf52fd4752f49d8c0e92e6a78c6d8a667be57f0ea126e30b0d8f8fe8b71` |
| `artifacts/x01-fault-window/two_of_four-node-3-process_stopped.json` | `c381db859bc07f5c6529526e2463ff0d68cc8d95f1c129678411cb5e45cb192b` |

The pre-fault policy fixed node3 `initial_pid=1786508`. Before the 2/4 fault, the Stage A script legitimately restarted node3; the F01 process-generation record gives PID/start-ticks `1786508/3245121` then `1861346/3331337`, both with the same node3 DB cwd `(dev=2049, inode=37096013)`. The X01 2/4 stop raw event proves it stopped PID `1861346`. Node4's 3/4 stop was `1826132`, restart `1840535`, and 2/4 stop `1840535`. The checker at `scripts/x01_window_evidence.py:261-263` incorrectly requires node3's 2/4 stopped PID to equal the policy's earlier `initial_pid` despite that planned restart. The policy was frozen before the 3/4 fault; this is an in-run pre-fault freeze, not an externally precommitted policy.

Next control: bind each stopped PID to an ordered, raw-OS-backed process-generation chain (including the planned restart), preserve old→new continuity and DB/PQ/ADNL/binary identity, and keep wrong-generation/alias mutations red. Then run one new exact committed tree serially. The existing b207 failure and raw artifacts must remain unchanged. A03 ledger integration does not close X01.
