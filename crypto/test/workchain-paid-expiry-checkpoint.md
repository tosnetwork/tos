# Paid expiry checkpoint (partial)

Specification: memo `a131b9bb`, SHA256 prefix `187dbc79290d6816`.

The owner Withdrawal branch now retains the full version-4 control envelope
across subsequent prepares. Its proof context binds the actual authenticated
predecessor root, not a legacy encoding of the cryptographic projection.
Already authenticated phase-1 records expire only at height strictly greater
than Q + settlement_blocks. Expiry removes records only; it creates no receipt,
Native transfer, fee or sequence increment. Phase 0 is never expired using Q=0.
The owner's proof still must pass before any update is published.

## Fresh evidence

- `test-m3-live` built: `/tmp/uno-paid-owner-build.log`.
- Association target built: `/tmp/uno-paid-expiry-build.log`.
- Default CTest `test-workchain-withdrawal-paid-expiry-component-partial`: 1/1.
- Isolated shadow-header mutants compiled and executed the same PaidExpiry test:
  - change `<=` to `<`: exit 1 at `at_boundary.closed.empty()`;
  - remove phase-0 exclusion: exit 1 at `phase_zero.closed.empty()`;
  - write available_revision during expiry: exit 1 at the full encoded-root
    comparison against a root changed only by removing the W record.
- Logs: `/tmp/uno-paid-expiry-{height,phase0,state}-red.log`.
- Original source was not mutated; original CTest passed again after controls.

## Observation and execution limits

The observation is a complete encoded account fixture, including its control
envelope and empty pending collections. The path is the expiry helper called
by a component test, NOT a Native accepted block or a nonempty-pending test.
No formal contract slot closes. Failed remains 0/10; prepare remains 0/9.
The isolated mutations above are recorded executions, not registered recurring
mutation runners. No guard is retired.

Real row-4 publication remains unfinished: live predecessors currently have
phase 0, and the account engine read view does not yet carry authenticated queue
observation needed to establish phase 1. Do not inject Q into a fixture and
describe it as live evidence. Other owner operation kinds are not integrated.
This checkpoint does not claim a new live regression run.

For the later late-return work, the current normative table gives both rows 3
and 6 the same credit and P/W deltas. Neither those totals nor the credit alone
distinguishes the branches: the negative control must observe window dispatch.
