# Experimental balance-kernel transcript

This transcript implements the authorized mathematical kernel, not the
unfrozen full transaction codec. Amounts are confidential; account and transfer
relationships remain public. No legacy transcript or Note format is accepted.

The initial Merlin domain is
`uno-v2/balance-relation`. Append, in order:

1. `protocol-domain`: the mandatory 80-byte domain defined in ABI.md, identical
   in layout to system encryption but under this distinct operation label.
2. u64 `relation` (SEND=1, COLLECT=2), then u64 `fee` in nanotomi.
3. u64 `max-balance`, then `max-value`.
4. `authenticated-context`: the complete caller-supplied context byte string.
5. u64 `point-count`, followed by each `public-point` in ABI order.
6. u64 `receipt-count`, followed by each `receipt-id` in ABI order.

Merlin supplies message framing. Scalars/points in proof arrays are canonical.
The context is authenticated by the future host, not by this library. No
default context, fee, expiry, policy identity or deployment network is supplied.
The public fee enters both the relation and the transcript: SEND proves
`a = a' + v + fee`; COLLECT proves `a + sum(v_i) = b + fee`.
The host must independently reconstruct the configured fee and protocol domain;
accepting caller-supplied values here does not authenticate their provenance.

Clone this state into separate subprotocols:

- AND: append `subprotocol=shared-witness-AND-v1`, then all `T` in equation
  order. Derive 64 bytes labelled `e` and reduce with from_bytes_mod_order_wide.
  Each witness has exactly one response z_l, used in every applicable row.
  Verify each row independently. Final responses cannot precede their own
  generating challenge; there is no later random aggregation.
- Range: append `subprotocol=range-v1`, then replay the pinned range transcript,
  including verifier-derived V commitments, A/S, y/z, T1/T2, x, scalar responses,
  w, inner-product L/R/u, final a/b and c. Preserve c derivation but do not use
  it to merge the inner-product and polynomial residuals.

The two subprotocols bind the same public J/C and context. Range complements
are group-derived commitments, not unguarded subtraction of secret integers.
Prover randomness remains mandatory. All new context and proof-message binding
requires independent security review even though Merlin itself is reused.

The active artifact is `fixtures/balance-kernel-v2.txt`; the v1 artifact is
historical and is not accepted by the v2 test consumer or exported interface.
Frozen tests include complete SEND and COLLECT k=1..8 proofs, statement and
proof perturbations, every independent row's negative witness, and an
independent C transcript known-answer vector. Changing transcript events must
fail those tests, not silently regenerate expected output.
