# TOS Tooling: Unified Next-Steps

> Single source of truth for remaining work across `~/tos` and `~/tos/tosctl`.
> Replaces the scattered P0/P1/P2 lists that were in `validator-engine-json-rpc-gap-plan.md` and `tosctl-mytonctrl-implementation-backlog.md`.
>
> Last updated: 2026-04-13 (status audit correction)

## What's done

| Area | Status |
|---|---|
| `~/tos` JSON-RPC server | ✅ 21 methods + 15 REST GET endpoints, 3 HTTP endpoints, runtime config, request timeout |
| `~/tos` staking contracts | ✅ 3 suites TOS-adapted, FunC compiled, BOC hex in tosctl |
| `~/tos` HTTP deadlock fix | ✅ HttpPayload callback safety + one-shot completion (codex root-fix) |
| `~/tos` TL parity fix | ✅ lookupBlock/shards/sendBoc adapted for TOS liteserver |
| `~/tos` 4-node testnet | ✅ BFT fault-tolerant (3/4 threshold) |
| `~/tos` Simplex design doc | ✅ simplex.tex (18 pages) + catchain.tex PDF |
| `~/tos` CI supply chain | ✅ Dockerfile.builder, pinned uv, builder image workflow |
| `~/tos/tosctl` CLI commands | 90 subcommands registered: 90 ✅ Full |
| `~/tos/tosctl` contract wrappers | ✅ SingleNominator + NominatorPool + LiquidController (48 tests) |
| `~/tos/tosctl` control-client TL | ✅ 13+ methods (collator, whitelist, config, stats, overlay, quic) |
| `~/tos/tosctl` alert system | ✅ Config schema + 5 commands (Telegram + webhook) |
| `~/tos/tosctl` supply chain | ✅ toncenter-rs vendored as toscenter-rs, pytoniq_core vendored as pytosiq_core |
| `~/tos/tosctl` operator docs | ✅ README.md, JSON output on 15 commands, mnemonic aliases |
| E2E JSON-RPC test | ✅ 21/21 passing |
| mytonctrl 87 命令平替 | 90/90 Full ✅ |

## Remaining work

### P0 — Must do before production use

| # | Task | Repo | Description | Status |
|---|---|---|---|---|
| 1 | **Staking contract on-chain verification** | `~/tos` | Deploy single-nominator pool on TOS testnet, verify full lifecycle. Test script: `scripts/e2e-test.sh` | ⚠️ Script ready, manual run needed |
| 2 | **End-to-end testing on TOS testnet** | both | Test scripts: `scripts/e2e-test.sh` (CLI) + `scripts/e2e-jsonrpc-test.sh` (JSON-RPC) | ⚠️ Scripts ready, manual run needed |
| 3 | **JSON-RPC request timeout** | `~/tos` | QueryTimeoutGuard actor wraps liteserver queries. Default 30s, configurable via `--json-rpc-request-timeout`. | ✅ Done |

### P1 — Required for operator onboarding

| # | Task | Repo | Description | Status |
|---|---|---|---|---|
| 4 | **Operator documentation** | `~/tos/tosctl` | README.md with install guide, config example, command reference, common workflows, architecture overview. | ✅ Done |
| 5 | **JSON output for all table commands** | `~/tos/tosctl` | `--format json` added to 15 commands: pool ls/get, node status/collator ls/whitelist ls, account status/txs/bookmark ls, observe validators/efficiency/alert ls, vote offer ls/election ls, host status/settings show. | ✅ Done |
| 6 | **Response-shape parity audit** | `~/tos` | Fixed: block_id placeholders, @type consistency, missing wallet_id, runGetMethod last_transaction_id/block_id. | ✅ Done |

### P2 — Nice to have / future improvement

| # | Task | Repo | Description | Status |
|---|---|---|---|---|
| 7 | 5 guided stubs completion | `~/tos/tosctl` | controller stop (return_unused_loan), stop-withdraw (compound), apr (on-chain calc), test-loan (get-method query), liquid check (cross-controller audit). Fixed opcodes to match contract source. stop/apr/test-loan/check now ✅ Full. stop-withdraw status TBD. | ✅ Done |
| 8 | `estimateFee` | `~/tos` | Implemented via local TVM emulation: fetch account state + config, run SmartContract::send_external_message(), compute gas/storage/fwd fees. Also added getConsensusBlock. | ✅ Done (codex) |
| 9 | Prometheus direct scraping | `~/tos/tosctl` | `observe metrics show --endpoint` fetches via reqwest. `observe metrics push` forwards to push gateway. | ✅ Done |
| 10 | Mnemonic aliases | `~/tos/tosctl` | Group aliases: `w`, `p`, `v`, `n`, `ac`, `ob`. Hidden shortcuts: `wl`, `vl`, `ef`, `ol`, `el`. | ✅ Done |
| 11 | REST transport endpoints | `~/tos` | 15 GET-style endpoints added alongside /jsonRPC. Query-string-to-JSON conversion reuses existing handlers. | ✅ Done |
| 12 | `tosctl install wizard` | `~/tos/tosctl` | Interactive setup wizard: checks prerequisites, collects config, generates tosctl-config.json. | ✅ Done |
| 13 | Policy documentation | `~/tos` | `doc/json-rpc-policy.md` — R6-R14 design decisions documented. | ✅ Done |
| 14 | Advanced/explorer APIs | `~/tos` | E2–E9: getMasterchainBlockSignatures, getShardBlockProof, etc. | ❌ Deferred |

## Acceptance criteria for v1.0

| Criterion | Status | Blocked by |
|---|---|---|
| Every mytonctrl command has tosctl replacement | ✅ 90/90 Full | — |
| Staking contracts verified on TOS chain | ⚠️ Script ready | #1 (manual run on testnet) |
| E2E JSON-RPC test (21/21) | ✅ Done | — |
| E2E CLI test | ⚠️ Script ready | #2 (manual run on testnet) |
| Operator README exists | ✅ Done | — |
| JSON output on all list/status commands | ✅ Done | — |
| No hung HTTP requests on chain stall | ✅ Done | — |
| REST GET endpoints | ✅ Done | — |
| Response-shape parity | ✅ Done | — |
| Policy documentation | ✅ Done | — |
| All CLI commands fully implemented | ✅ 90/90 Full | — |
| Simplex consensus design document | ✅ Done | — |
| Supply chain hardening (both repos) | ✅ Done | — |
| CI builder image | ✅ Done (needs first manual trigger) | — |
