# Preflight allowance consistency

Source: `f62cecf09111cf439bd9a29f8108f3697fbb4c53`. This follow-up adds static checks, not C2 production accumulation.

| Input, hard = 2 | Resolved result | Installation |
| --- | --- | --- |
| allowance = 0 | ConfigInvalid / ZeroLimit | Rejected with existing zero-bound diagnostic |
| allowance = 1 | ResolvedBatchInputPolicy | Accepted |
| allowance = 2 | ResolvedBatchInputPolicy | Accepted |
| allowance = 3 or 2^32 | ConfigInvalid / PreflightAllowanceExceedsBlockBudget | Rejected with preflight-budget diagnostic |
| allowance = UINT64_MAX | ConfigInvalid / PreflightAllowanceExceedsBlockBudget | Factory control; not separately exercised at installation |

The wire value is asserted unchanged before classification. Comparison widens the uint32 hard limit to uint64; it never narrows the allowance. Factory ConfigInvalid remains a local authenticated-state failure when resolved from authenticated configuration. The installation API returns a configuration Status error. No candidate-invalid path or execution gate was added.

All 129 WorkchainBlock cases passed after explicit rebuild. This includes the existing distinct old-tag and missing-allowance framing checks. The default all build passed with FUNC_BIN, FIFT_BIN and TOL_STDLIB removed from its environment, in the existing Ninja build directory (not a fresh-directory claim). Regenerated genesis bytes equal the committed fixture. This is not a full CTest regression claim.

Six isolated mutations remove the zero check, remove the budget check, narrow the allowance, reject equality, substitute the error code, and remove the actual installation check. Each failed at its recorded assertion. After every restoration both copied test and dispatch objects were explicitly recompiled and the executable relinked; both focused tests then passed. Repository and copied restored bytes match the report hashes. No repository source mutation was used.

`raw.tar.gz` retains successful and unsuccessful logs, commands, generated genesis inputs/outputs, control scripts and copied sources; its members are hashed in report.json. Compiler objects and executables are omitted. Review working material remains outside the repository. The first compilation failure and the accidental unrelated-loop failure are retained, not policy-guard evidence. The interrupted first control attempt is not counted.

Equality proves configuration acceptance only. With an allowance equal to hard, arithmetic permits one full reservation, but rejection of a second real invocation is NOT measured here: the production preflight path remains closed. C2 accumulation, independent validator reconstruction and their boundary controls remain blocked on the separately required gate decision. No claim of bounded production execution follows from these static checks.
