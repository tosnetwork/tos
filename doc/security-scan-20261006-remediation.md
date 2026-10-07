# Security scan remediation: 2026-10-06

Scan run: `wfr_587879028e36a0b20fa2c768bf6bc2d5a88c5b179aea0c45136dd66b204afb60`.
Scan revision: `9960de239fda55dd9888cd23893bd694af130e44`.
Review baseline: `6da705c8ad6e5a1dd118f11de819e0e542416540`.

All twelve findings remain present at the review baseline. The affected source paths are unchanged from the scan, except for unrelated address parsing additions in nodectl/utils.rs. This is source confirmation; runtime controls and fixes are recorded separately below. No new Cloud scan has been launched.

| # | Finding ID | Severity | Finding | Baseline | Remediation status |
|---|---|---|---|---|---|
| 1 | `csf_0e44054d12cb535e11a3d3f2` | high | Source rotation bypasses ADNL decrypt throttling and creates unbounded pre-authentication state | Present | Pending |
| 2 | `csf_c0cba186c5954d7050a7af3f` | high | Generic multisig authorizations are not bound to the network global ID | Present | Pending |
| 3 | `csf_80e522ac5cc5420f8641dd26` | high | Node-control configuration writes expose inline keys and credentials through permissive, symlink-following creation | Present | Pending |
| 4 | `csf_d565d7fc0f942dc96e8f05f4` | high | Release and builder pipelines execute downloaded tooling without independent integrity verification | Present | Pending |
| 5 | `csf_c8a7cfb31c272ff0f43fe776` | high | Ambiguous HTTP framing permits request smuggling across proxy boundaries | Present | Pending |
| 6 | `csf_eef543a1772e8a986f353a24` | high | TOS Connect trusts an unbound bridge sender as the wallet and permits sender replacement | Present | Pending |
| 7 | `csf_762872508293ff63bfe3acca` | medium | JSON vault persistence uses a predictable symlink-following temporary path | Present | Pending |
| 8 | `csf_7cbc3b2d69ccf923770f6fd9` | medium | RLDP response forwarding emits chunked bodies without a matching HTTP framing header | Present | Pending |
| 9 | `csf_ed36e7ef66dea1203e68ef69` | medium | Legacy wallet contracts accept forgeable Ed25519 authority-key encodings | Present | Pending |
| 10 | `csf_b8df2f7a85245ada30915d98` | medium | Lite-server error messages are inserted unescaped into explorer HTML | Present | Pending |
| 11 | `csf_91c17590b773e98f2828c242` | medium | Chain-RPC API keys are accepted in process-visible command-line arguments | Present | Pending |
| 12 | `csf_3a15ea0edf9f75b9a8704613` | low | Validator can skip mandatory dispatch-queue priority after cleanup and regrowth | Present | Pending |

## Validation

Pending. This draft is not merge-ready. Contract code and wire-format changes require updated builders, regenerated artifacts, strong-key positive controls, and targeted red/green controls. Changed native and Rust boundaries require their relevant build/test gates; required branch checks remain hard gates.

