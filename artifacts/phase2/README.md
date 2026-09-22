# Phase-2 ceremony, in progress

**Open. One contribution. Not closed, and not yet trustworthy.**

The procedure is `doc/shielded-pool-phase2-runbook.md`. This says where this
particular ceremony has got to.

## The announcement

| | |
|---|---|
| circuit | 18,107 constraints, 19 instance variables, QAP domain 2^15 |
| phase 1 | Zcash Sapling, slice `1bfd7acdb3ecbfaa…` (committed, `artifacts/phase1/`) |
| starting key | `018853105392e4e0ef82ae59514f137b1f1a19892023b70b72ef58941b017c04` |
| opening transcript | `7dcfafe1626b5586d5713654c55cc0887590fd789c391ecf1e28bfaf93e66287` |
| **beacon** | **NOT NAMED — see below** |

Every participant rebuilds the starting key from the committed slice and must
get that digest. Anyone who does not is contributing to a different circuit
and should stop.

## The chain so far

| # | who | contribution | attestation |
|---|---|---|---|
| 1 | an automated agent on the operator's machine | `b113fd1d4579e25a…` | `attestation-1.txt`, **unsigned** |

Contribution 1 **adds nothing to the trust set beyond the operator's own**.
The agent cannot see the scalar, but the trust boundary is the machine and the
machine is the operator's; counting it independently would be counting the
operator twice. It is here because a chain has to start somewhere.

**So this ceremony currently rests on nobody.** It starts being worth
something at contribution 2, if contribution 2 comes from someone who can fail
independently of the operator.

## Two things to fix before contribution 2

1. **Name the beacon.** Source, exact height or round, and witness, published.
   Its whole property is that nobody could predict it while contributing, and
   that is about *when* it was chosen -- `phase2-verify` confirms a step is
   that beacon's and says nothing about when the bytes were picked. It was not
   named when contribution 1 was made and this record says so.
2. **Decide whether unattested contributions count.** Contribution 1 is
   unsigned on purpose: an agent has no identity that predates this ceremony,
   and a key generated to sign with would be worth exactly as much as no
   signature while looking like more. If the operator wants to stand behind
   it, the right signature is theirs.

Nothing is deployed and no address is published, so **redoing this from
scratch costs only the time**. That is the cheapest it will ever be.

## If you are contribution 2

From a checkout at the commit named in `attestation-1.txt`, on your own
machine, having read `tools/shielded-pool-ceremony/src/secret.rs` and
`entropy.rs` -- about 280 lines, and the whole of what protects your scalar:

```sh
./scripts/shielded-pool-phase2-contribute.sh artifacts/phase2/ceremony \
    --sign-with gpg:<your-key-id>          # or ssh:<your-key-file>
```

It builds from source rather than running a binary somebody handed you, which
is the point. It takes about two minutes, almost all of it rebuilding the
starting key so that you are checking it rather than trusting it.

Then publish your attestation and push the updated directory.

## What is in here

```
ceremony/key.bin            the proving key as it stands  (~6 MB, replaced each step)
ceremony/contributions.bin  every contribution, 672 bytes each, in order
ceremony/ceremony.json      what each step was, and the digests
attestation-N.txt           what participant N says they did
```

**There is nowhere in any of it for a secret to go**, which is why it is in a
public repository while the ceremony is still running.
