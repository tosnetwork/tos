# E12 Dispute local-chain evidence (11ddcad18)

The committed `11ddcad1839b60423f92eca0e3b6d1fa6a4238bf` tree ran
`TOS_BUILD_DIR=build PYTHONPATH=test/tostester/src uv run python -u scripts/dispute-e2e.py`
through `script -q -e -f -c`. The wrapper exited 0; its console records
`47 PASS`, no `FAIL`, and `RESULT: ALL PASS`. The in-run manifest records a
clean tracked tree, the script/test SHA-256 values, and the validator-engine,
DHT, and tosctl binary SHA-256 values. Thirteen focused offline tests passed
before the run.

Retained raw files (all relative to the repository root):

| File | SHA-256 |
| --- | --- |
| `test/integration/.e12-dispute-11ddcad18-20260925-console.typescript` | `913c6ebacf4ea12f50bcd5b63a186eb6e9add2ead875daed3548e44e8ea29809` |
| `test/integration/.e12-dispute-11ddcad18-20260925-network/manifest.json` | `31dfc241e148559e05ae379e49d078d4b06b5eeca1963a64fb84da8dbe74e988` |
| `test/integration/.e12-dispute-11ddcad18-20260925-network/negative-evidence.jsonl` | `a8e3729703d8c88084501da71d60d1be7d81c44c81b2cad7c56ac34c1c4249f1` |
| `test/integration/.e12-dispute-11ddcad18-20260925-network/cli-transcript.jsonl` | `b62e615cbbc4f54831a2a973188a329c96e6ac4e166c40c69ed8700ab16658e2` |
| `test/integration/.e12-dispute-11ddcad18-20260925-network/rpc-transcript.jsonl` | `fc555670b0bcb83f733e12e6357c3917d5e093a19d956e304e2b4590490c0bc9` |

The 12 negative receipts cover exact Dispute VM exits 2000, 2001, 2002,
2007, 2006, and the unsigned-rule cell-underflow exit 9. Each receipt has
one successful wallet send, the same outbound/inbound message hash at the
Dispute, one exact bounced message returning to the wallet, the expected
aborted compute exit, two subsequently advancing finalized masterchain
headers, and unchanged Dispute state. A `jq` cross-check found all 12
wallet-to-Dispute and Dispute-to-wallet hash joins and head orderings true.
The positive cases exercised deployment, evidence submission, claimant and
split rulings, attestor rotation/revocation policy, and local record lookup.

Scope: one local PQ validator and one DHT process, not a multi-validator or
release-scale run. The Python RPC transcript covers this script's direct
JSON-RPC calls; tosctl's separate RPC requests are not captured there. The
CLI transcript retains its arguments, exit codes and raw output. This is
local evidence for independent review, not unilateral E12 signoff or proof
of transport authentication. E14 and the independent indexer risks remain
open.
