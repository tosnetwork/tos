# Wave 2: public scope and test-genesis guards

## X-2: protocol declaration versus local installation

The existing public ingress constructor declares BlockTransition scope. Reserved
native TVM engine keys have intrinsic AccountCompute scope; pure binding
validation now rejects that conflict, including configuration loaded without a
transition history. It does not query a local engine registry. Custom engines
use the authenticated ingress declaration; this change does not freeze a UNO
selector, add a config field, or introduce a whitelist of installed engines.

Receiver resolution follows that declaration. A node with only an AccountCompute
implementation installed for a declared block engine cannot silently fall back
to it. Direct account resolution also rejects such a declaration. Missing block
execution capability is a local readiness failure, not permission to reinterpret
the config. With no declaration, existing account execution remains available.

The two new tests check TVM rejection and custom declaration acceptance with an
empty registry, then install an intentionally wrong local compute engine and
assert **zero config callbacks**, with a no-ingress positive control. Removing
the reserved-scope check accepts the invalid binding; removing declaration
enforcement calls the wrong engine twice. Both tests were observed red and the
mutations restored. Existing tests that paired a TVM descriptor with an unchanged
Counter ingress entry now correctly expect resolution failure rather than
treating that contradictory fixture as valid native configuration.

## A6-5: public keys are never deployment keys

`counter-masterchain-genesis.fif` contains a publicly known test validator key.
It is **for disposable test networks only; never deploy it with real value or
use that validator key for any real network**. The script now asserts global_id
-23901 before creating any state. Changing its global_id is not a safe way to
turn this fixture into a deployment template; replacing or deleting the guard
does not make its public key secret.

`test-counter-genesis-domain` runs the actual script prefix in create-state,
with its real preamble, before the first state-creation command. The test domain
reaches an observable marker; three other nonzero domains must fail before that
marker. Removing the guard lets a non-test domain reach the marker and turns
the test red. This does not depend only on an error string or an unrelated
missing fixture. Failed experiment directories are printed and retained.

Logs: `build/wave2-{scope-binding,scope-resolution}-mutation.log` and
`build/wave2-genesis-domain-mutation.log`. The test guard is an accidental-use
barrier, not a defense against someone deliberately editing the script.
