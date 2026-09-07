# Dual Native ingress boundary review disposition

Status: reviewed development snapshot; owner authorized this limited delivery
in memo commit `1b2be223`. This is not a deployable multi-account host.
This is not M1 acceptance or permission to open dual-entry admission.

Verbatim review: `~/memo/reviews/uno-v2-dual-ingress-review.txt`.
The reviewer inspected source and generated codecs; it did not run the pending
removal controls. Runtime evidence must be reported separately.

## R1: admission ahead of execution — accepted, development snapshot only

A fresh closed-admission descriptor can currently install a dual policy through
the configuration predicates, but the only registered block-engine interface
rejects it. Opening transport admission before the receiving multi-account path
exists is not made safe by calling the work staging. The continuity guard also
prevents a casual rollback. Do not commit this as installable V2 configuration.

The owner selected a development snapshot rather than withholding this unit
until complete host integration. `SUPPORTED_VERSION = 15` does not prevent
installation: both collator and validator only log versions above that value.
The sole configuration-installation code gate is `valid_config_data`, through
its common ingress-presence and binding checks; its v16 threshold does not prove
that the binary has multi-account execution capability. The separate reader gate
does not supply that proof either. No check consults a local engine registry to
decide configuration validity.

Do not enable v16 with capBlockTransition for this profile before binaries with
the complete multi-account executor are broadly deployed under the approved
readiness procedure. Version is a release-process proxy, not a code guarantee
of execution support. Release dry-run coverage must include v16 enabled before
that deployment; this snapshot does not implement that rollout acceptance gate.
The two version-warning sites are unchanged. Changing their global behavior
requires separate authorization. R1 remains an activation obligation, not a
claim that development-snapshot authorization fixes missing execution.

The review's alternative of allowing v2-to-v1 rollback is not selected: a config
pair alone does not establish that already committed custody-bound messages and
obligations have disappeared. No migration evidence or exception is invented.

## R2: resolver coverage — fixed, runtime control red

`SenderResolvesIngressWithoutForeignEngine` now supplies a v2 Config84 entry to
the actual resolver, requires exactly both distinct destinations, and passes its
result into Native destination rewriting. It accepts each role and rejects a
third address without a foreign engine. This replaces manual map construction
as the evidence for the resolver insertion itself; the older direct routing
test remains useful for the destination predicate independently. Removing the
resolver's custody insertion and rebuilding fails the exact set-size assertion
(1 instead of 2), before any downstream transport check.

## R3: unreachable custody fetch failure — fixed

Removed the new unreachable error branch. Exact 737-bit shape and preceding
fixed-width reads guarantee that the final 256 address bits remain. The comment
states this structural invariant; the truncated fixture tests the shape guard,
not a fictional short-read branch. No new exception classification is added.

## R4: classify every configuration fault as candidate-invalid — disputed

An invalid proposed configuration and inability to execute an authenticated
configuration are different sources. A validator lacking required execution
support cannot label a valid candidate invalid merely because its own binary
cannot execute the configuration. Conversely, malformed proposed configuration
must be rejected before installation. Plain Status is not a provenance proof.
The current mixed caller behavior is a real integration obligation; it is not
closed by changing every failure into reject. Typed resolution/provenance and
the complete V2 boundary must be checked before enabling this profile.

## R5: singleton receiver restriction — accepted, retained

The singleton-engine rejection must remain until receiver routing, complete
inbox treatment, multi-account execution and independent reconstruction are
connected together. Neither the sole AccountBlock check nor the current
single-destination receiver can simply be removed. No code here authorizes that.

The review confirmed generated/handwritten tag and width parity, both v16 gates,
unchanged anycast prohibition, shared send/bounce address rewriting and the lack
of new financial arithmetic. Existing constructor exception propagation is not
reclassified by this unit. Production activation, end-to-end multi-account
evidence and migration remain incomplete.

Seven rebuilt manual controls failed: custody insertion, role distinctness,
configuration-version gate, reader-version gate, singleton-engine rejection,
custody continuity and address membership. Restored production/test targets
built; four CTests passed in 5.13 seconds. This is manual evidence, not recurring
mutation CI. Provisional raw evidence is in
`~/memo/reviews/uno-v2-dual-ingress-evidence.json`; it identifies the uncommitted
source diff and must be refreshed if the installation policy changes.
