# Slice 6 Activation And Rollback Plan

## Status

Repo-side Slice 6 dogfood is complete. Real production workchain
activation is pending.

No production activation height is declared in this commit. The
activation height remains `TBD` until a deployment operator signs off on
validator support, replay fixtures, and rollback readiness.

## Capability Flags

| Surface | Repo-side status | Production flag |
| --- | --- | --- |
| Delivery id / dead-letter helpers | Available | No validator behavior required |
| BackPressure emission | Payload validated | Disabled pending information-leak review |
| Scheduled delivery | Stdlib/model available | Disabled until validator scheduler gate |
| `OP_MONITOR_DOWN` | Stdlib available | Enabled for contract-level dispatch |
| `extra_flags` bit 3 | Reserved | Disabled |
| Supervision stdlib | Available | Contract-level only |
| Capability grants | Available | Contract-level only |

## Activation Checklist

- Re-run the full Slice 1-6 verification suite.
- Confirm `scripts/check-slice-6-release-package.py` is green.
- Confirm no contract schedules from caller-controlled message time.
- Confirm every dead-letter, scheduler, monitor, supervisor, and
  capability state surface has declared budgets.
- Confirm BackPressure production emission remains disabled unless its
  separate review explicitly approves it.
- Confirm `extra_flags` bit 3 remains rejected unless a synchronized
  validator-mask amendment is approved.

## Rollback Plan

- For repo-side stdlib use, rollback is source-level: stop importing the
  Slice 6 helper and deploy previous contract code.
- For any future scheduled-delivery validator gate, rollback must reject
  new scheduled entries while continuing to process or refund already
  accepted funded entries.
- For monitor/supervisor/capability contracts, rollback must preserve
  existing state and add a migration getter exposing outstanding handles,
  revoked ids, dead-letter counts, and scheduled handles.
- BackPressure emission rollback is simple while disabled: no production
  messages are emitted.
