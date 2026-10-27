# Recorded authenticated self-pay execution inputs

These bounded public inputs were captured from a fresh isolated three-validator
VM16 chain running source-bound f2d2d391 tools. They contain an authenticated live
zerostate-to-target PQ proof, same-target complete configuration and basechain
account proof, and one external request signed using the public hexadecimal11
fixture seed. The retained manifest identifies each input and the node source.
No secret or private runtime key material is included.

The test supplies the locally recorded clock, an explicit anchor-only initial
live state and the exact signed message to the current one-shot adapter. It
checks execution, payment/fee/post-balance projection, a reserialized forged
signature that reaches exit1808 with no transaction, damaged account material
refusal and byte-identical state on restoration. These are replayable recorded
proof inputs, not a claim that their timestamp is fresh at test execution time.

The capture's getter was only used to acquire and verify complete execution
material. The simulation request has no getter or selected-config request, so
its live authentication and actual execution occur in the same adapter call.
The request was not broadcast. This is not phone custody/payment, deployment,
release-network acceptance, or a fee guarantee. The expected transaction fees
are smaller than balance deduction minus outgoing value; fee budgeting must
use the full balance/value/phase semantics.

Capture commands, tool/source identities, original failures, cleanup receipt
and raw evidence are indexed in the companion mobile-wallet handoff memo.
