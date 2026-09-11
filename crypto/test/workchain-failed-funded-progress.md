# Funded in-window Failed: transition checkpoint

## Native connection prerequisite: explicit test configuration

Against memo `d8c6b463` / specification `cf7f0f4569e2638e`, the test business
configuration now has an optional version 4 carrying `withdrawal_limit` and
`issuance_billing_units`. It requires the existing explicit component tariff;
old layouts do not synthesize either new field. The 736-bit root retains four
references. This is a TEST layout, not frozen protocol initial values.

`ConfidentialInput.FailedParametersExplicitAndBound` checks round trip, absence,
field binding and incompatible inputs. Default focused CTest passes 1/1.
An isolated decoder mutant substitutes the seven proof-work units for the
explicit four billing units: the actual test exits 1 at `7 != 4`. The first
control build accidentally included both original and shadow headers and failed
to compile; that failure is NOT evidence. The corrected isolated build executes
the named test. Restoring the normal build returns to green. Local logs:
`/tmp/uno-failed-config-control-H8ZGw8/{build.log,red.log}`.

This prerequisite does not yet connect `M3NodeEngine` custody dispatch or Native
publication. The six-test host contract remains 0/6; neither sequence expiry nor
the prepare AST trigger is retired. Next: consume these explicit fields in the
registered engine and pass the complete three-account write set and fee effects
through the existing inbound allocation overlay, then test serialized Native
outputs and failed publication. No production consensus file changed here.

D61 inventory correction: the earlier eight numbered points covered seven
unique files, while B counted eight unique files including its own
`test/test-workchain-m5-accounting-assertions.cpp`. Equal counts did not identify
equal sets; this test consumer must remain in the union inventory.

Normative basis: memo `271b2d86`, SHA-256 prefix `d309dc6a5158f3fe`.

`prepare_workchain_failed_funded` executes real metered v2 system encryption
after the existing strong-association helper matches the actual envelope Message.
It consumes one staged coordinator sequence, encodes one settlement-origin
receipt and removes the matched open record in the returned account root.
It returns separate recovery/P/W amounts and Native state/compute fee components.
The caller must authenticate inputs and atomically publish these with Native
import/fee settlement. No registered-engine caller is installed yet.

The deliberately narrow path requires phase 1 with an open height window, an
active account, an available system slot and enough reserve for recovery loss,
slot fee and compute fee. Unsupported cases return an error, not a fabricated
Failed/Paid/bucket outcome. There is no shortfall, late-return, Paid or sweep
implementation in this change. No coordinator subsidy is generated.

## Executed evidence

Build target: `test-workchain-withdrawal-association`.
Default focused CTest passes 1/1, including `FailedFunded.RealIssuanceAndEncodedSequencePair`.
Two real ABI reconstructions return identical encoded account roots and consume
7 proof-work units each. Explicit synthetic transition inputs (not frozen or
authenticated business-configuration defaults) use x=100, recovery=70, reserve=100,
slot=2, base=3 and issuance billing units=4. Thus compute=12, receipt=156,
released P=100 and released W=200. Encoded coordinator sequence goes 10 to 11;
decoded receipt sequence is 11 and its origin retains the matched Attempt ID.
The Message hash is the actual imported Message hash. Old input roots remain
unchanged. Insufficient verifier allowance and late height return no result.

Isolated control: omit successful sequence installation in a copied transition
header, compile the same test against it, and execute real encryption. Exit 1
occurs at the decoded coordinator comparison `10 != 11`, not setup/compilation.
Restored focused CTest passes. Local logs are under
`/tmp/uno-failed-sequence-control-UlImJ4/`.

## Not yet earned

This observes returned encoded roots, not a Native block's committed state.
No Native balance is installed by this helper; returned recovery/P/W values are
not evidence of ledger publication. B's six real-host contracts remain **0/6
ready**, and its runner still reports HANDOFF_NOT_READY. The sequence guard
still passes because the new producer is not reachable from its registered
engine roots; it is not retired or weakened. The AST trigger is unchanged.

Next: connect the registered engine's custody dispatch to this transition using
authenticated fee/limit configuration and predecessor account reads, then feed
its account/coordinator updates and fee effects through Native settlement. Only
that boundary can supply B's host nonpublication/publication controls. The
source-aware caller must classify neutral helper errors by provenance, not map
every association or encoding error to CandidateInvalid. Do not use this helper
as proof that inbox membership was authenticated.
