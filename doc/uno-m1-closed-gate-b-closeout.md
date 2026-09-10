# B closeout under the closed-gate M1 definition

M1 means mechanisms, prepared seams, and a correctly closed gate with correct
classification. It does not authorize gate movement. Current source review for
X-1/X-2 is pinned to `c55fa45e76929bb19329f0ebb93a34c04d250cde`; cited production
files are unchanged by this preparation unit.

## B-1 / B-2: prepared, not connected

`crypto/test/prepared/workchain-validator-local-decisions.h` is a test-only
executable specification of the two local decisions. The opt-in module compiles
and calls it in private tests. No production target includes it. Neither actual
validator visitor nor registry refusal is replaced, and no dormant production
call site is added. It is a preparation artifact, not a new validator path.

The custom flag feeds the legacy per-account `run_compute` context
(`transaction.cpp:2211`), so AccountBinding returns false. Local readiness
returns OK for a successfully resolved binding, without asserting complete
replay capability. Authenticated configuration failures propagate unchanged;
they do not become CandidateInvalid. The actual registry gate continues to
reject insufficient local capability by LocalUnavailable. When gate movement
is separately approved, the local semantics can be applied at the existing
visitors; this file must not be mistaken for already connected production code.

The private fixture resolves a real committed genesis through
`resolve_scoped_workchain`, once with a configuration-only account engine and
once with an empty registry. Four separate cases check custom=false, ready=OK,
and both missing-engine outcomes as LocalUnavailable. Five isolated mutations
change the custom answer, restore either old refusal, or misclassify either
local resolution error. Each must fail only its specified case and numeric
identity; the other cases must pass. Explicit target rebuilds follow restoration.
No transaction, export or live visitor counts are fabricated by this fixture.
No candidate carrier is needed here: these decisions only consume authenticated
configuration resolution, and do not acquire or interpret candidate input.

B-2 is complete: five isolated mutants each fail only the specified one of
four cases (1311, 1310, 1320, 1331, 1341); all restored cases and both registered
CTest runs pass. Source-bound records are in
`doc/measurements/uno-validator-prepared-decisions/`, pinned to `9eff940be`. The first compiler stop (explicit CSlice conversion)
is development evidence, not a guard result.

## X-1: mechanisms checked in implementation, not inferred from filenames

| Item | Actual implementation and consumers | Judgment under the proposed boundary |
| --- | --- | --- |
| Restricted records | `transaction.cpp:4910` checks participant context/account binding, prohibits ordinary phases/value movement and seals metadata; `:4947` onward rechecks it on serialization. `workchain-payout-overlay.h:163-166` actually calls participant preparation. | Private host mechanism exists. Live production/replay is not claimed. New-account registration participant support remains a later lifecycle dependency. |
| Custody message value ownership | `transaction.cpp:4529` prices payout; `:4600` builds custody/coordinator pair; `:4673` applies the checked allocation; `workchain-payout-overlay.h:138` consumes it. | Private Native allocation mechanism exists. Withdrawal authority, protocol lock and fee-schedule authorization are not supplied by this host plumbing. |
| Independent value flow | `workchain-allocation-overlay.h:141` decodes old/new balances, fees and message values from serialized Native artifacts; `:217` calls `verify_workchain_value_flow`; payout overlay also calls it at `:260`. `workchain-value-flow.h:25` checks bounded per-currency conservation and endpoint membership. | Artifact-derived private Native value-flow check exists. This is not an independent whole-block validator or protocol reserve reconciliation. |

B's judgment: these three satisfy **mechanism existence for private host
plumbing**, if that is the coordinator's M1 meaning. Do not silently broaden
this to independent whole-block replay: `workchain-account-replay.h` and
`workchain-payout-overlay.h:287` reuse construction functions, so shared bugs
are not excluded by their agreement. Business authorization/reserve accounting
and registration semantics remain outside this narrow mechanism conclusion.
The final milestone disposition belongs to the coordinator, not this table.

## X-2: D51 is implemented

`block.tlb:16` requires `k_accepted_target_rate_ms:uint32` in the current issued
constructor. `workchain-resource-policy.h:130-170` documents acceptance-time
cadence, requires it in the non-default constructor, serializes it and decodes
it. The encoder has no current configuration input. The test
`EngineConfigurationAcceptedCadence` (`test-workchain-block.cpp:260`) checks
explicit varied values, exact wire field, round-trip and omitted/retired forms.
Evidence is already in `doc/measurements/uno-m1-cadence-*`. Later identity schema
changes retained this field; it is not unowned or awaiting implementation.
Installation-time comparison remains the separately deferred obligation; resource
quota calibration remains M6. Neither is erased by completing the record field.

## A-2 factual handoff

`c55fa45e7` pins merged parents and tree, eleven passing CTests and binary hashes.
Readiness asserted the exact typed error, retained binding, confirmed delivery,
zero execution/transactions and no export. Earlier failures, an execution probe
and a nonzero transaction observation calibrated parts of the instrument.
There is no dedicated registry-entry/variant/refusal counter or downstream
execution-visitor-zero counter in this evidence. Successful raw sidecars were
removed by the existing lifecycle; only source-bound assertions and full
CTest/JUnit output survive. A was notified of this **partial** coverage and
will supply the missing gate-specific observations. No duplicate experiment
or bypass is authorized by this handoff.

## Historical records

The old fixture migration, instance implementation and five-item closeout notes
now carry local supersession notices without deleting their original claims.
Immutable measurement archives remain historical, bound to their original
commits. Rust migration is complete, genesis installation is legal under revised
D40/D52, the former eleven-check deferrals are empty, and the full permission
scan is green with fresh retired-content calibration. These changes do not
retroactively alter older failed runs.

## Prepared-code expiry

The registered private CTest first runs
`crypto/test/workchain-validator-prepared-expiry.py`. It scopes checks to the
custom/ready AccountBinding arms and requires their current LocalUnavailable
refusals (1350/1351). It does not compare the unrelated legacy arms bytewise.
Changing either production refusal expires the private preparation; its file
must be deleted and controls retargeted to actual production call sites when
the gate opens. This is a source lifecycle guard, not a runtime gate measurement
or a claim that the duplicated legacy branches cannot drift before that point.


**Registration correction:** The initial expiry implementation was registered
only with the opt-in private fixture. That was insufficient to ensure ordinary
CTest catches production connection. The source-only expiry check is now
registered unconditionally in crypto/CMakeLists.txt as
`test-workchain-validator-prepared-expiry`; it needs no native probe or optional
include. The private opt-in test still runs the same guard before its probe.
Historical opt-in evidence remains valid for that narrower registration scope.


**Native registration follow-up:** The root CMakeLists.txt now also defines
`test-workchain-validator-local-visitors` directly, adds it to `all-tests`, and
registers its wrapper by default. The historical optional module is only a
compatibility entry, with no duplicate definitions. Thus both the source-only
expiry guard and the private native decision checks run in ordinary CTest.
Private scope still means no live actor/call-site evidence; it no longer means
optional registration. Earlier opt-in measurements keep their historical scope.
