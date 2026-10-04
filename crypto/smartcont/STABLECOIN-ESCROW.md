# Stablecoin escrow: supported versions and deployment restrictions

The TOS Service Protocol stablecoin escrow holds a buyer's jettons for an
Accepted Quote and pays them to the provider on a valid Receipt, or back to the
buyer on refund. This file records which versions the repository's tooling
deploys and under what restriction.

| Version | Source | Status | Deployable by repository tooling |
|---|---|---|---|
| v1 | removed | **Retired** | Never |
| v2 | `tos-service-stablecoin-escrow-v2.fc` | **Experimental; accepted risk** | Non-production only, with `--non-production-test-deployment` |

The policy is enforced in `scripts/tos_service_escrow_deploy_policy.py`, which
`scripts/tos-service-stablecoin-escrow-deploy.py` applies to the code hash of
the StateInit before it reads any network configuration or key.
`scripts/check-retired-escrow-v1.py` (tested by
`scripts/test_check_retired_escrow_v1.py`) fails if the policy, or any
tooling, build or contract file, would let v1 be deployed again.

## Escrow v1: retired

Escrow v1 derived the address of its own jetton wallet from one fixed wallet
StateInit layout. Funding through a jetton whose wallet lays out its data
differently was credited to a wallet v1 never addresses; v1 then refused the
transfer notification, and the funding was orphaned.

The vulnerable deployment path was retired rather than repaired: the v1
source, frozen BOC, release manifest, build/embed/test scripts, CMake wiring,
the local paid rehearsal that deployed it (with its `--allow-deprecated-escrow-v1`
opt-in) and the evidence collector that read v1 state were removed. They remain
in Git history. The deployment policy refuses the v1 code hash by name, also
for non-production deployments.

This does not repair any v1 contract that was already deployed: deployed
contracts are immutable. Funds orphaned by such a contract are not recovered
by this change.

## Escrow v2: refused payouts can strand funds (accepted risk)

Escrow v2 returns funding sent through the wrong wallet instead of orphaning
it, but has a different limitation that is **accepted for this version, not
fixed**:

A release or refund sends a jetton transfer from the escrow's own wallet to the
recipient's wallet. If the recipient's wallet refuses the transfer (for
example, a wallet the stablecoin administrator has locked for incoming
transfers), the jettons bounce back into the escrow's own wallet and are
re-credited there **without telling the escrow**. The escrow stays in
`release_pending` or `refund_pending`, the funds stay in its wallet, and no
operation moves them. **Funds can be stranded indefinitely.**

This is deliberate. With the issuer's unchanged jetton wallet, the escrow
cannot distinguish a refused payout from one that was delivered but whose
acknowledgment was lost, followed by unrelated jettons arriving. An escrow-only
retry, a timeout refund, or a recipient-selected redirection could therefore
pay twice, or pay one party with another party's funds; an `excesses` message
from the recipient's wallet can be produced by any transfer naming the escrow
and its public query id, and the wallet balance proves nothing about which
transfer it came from. None of these alternatives is approved.

What the current version keeps:

- the funds-preserving behaviour: a pending settlement never pays from
  inferred state, and the regression tests in
  `tosctl/src/node-control/contracts/tests/tos_service_stablecoin_escrow_v2_sandbox.rs`
  hold it;
- the deployment restriction: repository tooling refuses to deploy v2 unless
  the operator passes `--non-production-test-deployment`, which states that the
  deployment is on a local or test network with test assets. The flag is
  recorded in the deployment evidence (`"non_production": true`).

### What production support requires

Production support for this escrow and token combination may be reopened only
with a new integration in which the token's wallet tells the escrow the
outcome of each payout, and that outcome is:

- **authenticated**: provably produced by the escrow's own jetton wallet (or
  the token's issuer contract) about a transfer the escrow sent, not by any
  account that can name the escrow;
- **request-specific**: bound to the exact payout (escrow, query id, amount and
  recipient), so it cannot be confused with another transfer or with unrelated
  jettons arriving;
- **replay-safe**: usable once, so the same outcome cannot settle or reopen a
  payout twice.

An issuer-supported wallet protocol that reports delivery or refusal on these
terms is an example. Generic `excesses` messages or balance inference are not.
Until such an integration exists and is reviewed, deploy v2 only for
non-production use.
