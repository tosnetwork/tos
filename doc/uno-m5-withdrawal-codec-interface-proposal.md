# Withdrawal codec interface proposal: no state location selected

Specification: `55663567` / `86832278bddf47a5`.
This is a field/API proposal, **not a callable interface or frozen wire layout**.
B owns record encoding; A must propose the authenticated location under D43.
No `block.tlb` change or new production parsing path is made by this proposal.

## Identities before authorization

Proposed helper inputs:

```
derive_workchain_withdrawal_id(network, source_address, consumed_auth_nonce)
derive_workchain_attempt_id(withdrawal_id, authenticated_attempt_sequence)
```

The first uses the existing network/global_id/genesis/workchain-instance and
full source/incarnation tuple, with a distinct Withdrawal constructor. It must
not change SEND/COLLECT or Close preimages. The second uses a distinct Attempt
constructor and the independent checked sequence required by section 7.3.
The helper accepts an explicit sequence; accepting it does not authenticate it.
No proof, current block hash, resulting state, or future Native created_lt may
enter either preimage. Numeric operation-kind allocation and final constructor
tags will be included in the actual codec delivery, not guessed by consumers.

**A input required:** where the independent Attempt sequence lives, its scope
and lookup key, and the atomic successful-install boundary. This proposal does
not substitute account auth_nonce or Native LT for that independent sequence.

## Permanent Withdrawal request

Proposed content, extending the existing permanent replay input family:

* Explicit Withdrawal constructor; claimed Withdrawal and Attempt IDs.
* Existing transfer claim fields: complete source, consumed nonce, old revision,
  key epoch, expiry height, separately authorized operation fee.
* Native destination (workchain/account), explicit principal x, outgoing fee q,
  original return reserve b, and claimed Attempt sequence.
* Proposed new available ciphertext and auxiliary J.
* Existing SEND-shaped authorization: eight commitments, six responses and the
  unchanged range proof. All authorization bytes remain committed in the block.

No public opening r, P_B or transfer C_t/D_tA/D_tB is transmitted. The host
acquires old P/C/D from authenticated state and gives A's statement constructor
the six balance points. Claimed IDs, old-state declarations and fees must be
compared with independently rebuilt inputs, not used as their sources.

## Canonical host context

The context needs independent operation/version/network identity, existing
rules/profile/config/fee-cut fields, source/incarnation/nonce/revision/key_epoch,
expiry, native destination, Withdrawal/Attempt identity and semantic request
binding. The return plan and authenticated settlement-window/allowance policy
must also be committed, because they determine the obligation being authorized.

The existing Rust constructor wraps its authenticated_context with an operation
domain, both IDs and four amount fields. B must define the host context bytes
once and let both host and wallet use that encoder; neither side may substitute
an unrelated SEND context or copy constructor tags manually.

**A input required:** whether the currently proposed authenticated return-plan
and obligation-policy identity can be rebuilt from the configuration slice, and
which field structure A will provide. No encoding of future created_lt occurs
in this pre-authorization context.

## Unclosed Withdrawal / W record

Required data includes source/return attribution, Withdrawal/Attempt identities,
Attempt sequence, principal, native payout destination, actual payout created_lt,
opening height and authenticated expiry rule, and the separate cost fields:

| Field | Meaning |
| --- | --- |
| outward_fee_paid | Already spent outgoing Native fee; never W or refundable reserve |
| original_return_reserve | Original b locked in custody |
| consumed_return_cost | Authenticated actual return loss plus system-slot cost charged against b |
| refundable_reserve | Remaining reserve attributable to this owner |

Where this reserve is fully reconciled, require checked
`consumed_return_cost + refundable_reserve = original_return_reserve`.
At opening they are respectively 0 and b. This is reserve accounting, not a
definition of the returned principal or the whole pending credit. In particular,
on Failed the gross returned principal and the remaining reserve must not be
conflated. Terminal dust disposition remains explicit under D65.

Actual created_lt is written only after Native message materialization and
must be checked against that actual message. It identifies a window-bound
obligation, not the pre-proof Attempt identity. Terminal records are removed
according to the specification; this proposal does not introduce permanent
per-payout history or a default empty obligation view for closure.

**A input required:** authenticated parent location, dictionary/index keys,
bounded traversal/read/write entry points, and aggregate W/P accounting fields.
The proposed record does not choose coordinator vs account vs custody storage,
invent an index, or infer a capacity limit. Until those inputs arrive, a record
codec cannot be represented as a usable authenticated obligation interface.
