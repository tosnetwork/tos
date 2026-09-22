# Phase-2 ceremony: the announcement

Published **before the first contribution**. Nothing below changes.

## The beacon

| | |
|---|---|
| source | **Bitcoin**, block at height **968100** |
| hash | `00000000000000000000ff8d744ddd9b97b1f3a29c514ac23eef72687bbcd4f8` |
| fixed at | Bitcoin tip 968106, i.e. this height was already six blocks deep |
| bytes used | the 64 ASCII hex characters above, exactly, no newline |
| sha256 of those bytes | `067b5b03a57f8d844b944b85d20217e75fed9f12e47238462322520c49338308` |

Anyone can check it against any Bitcoin full node or explorer:

```sh
curl -s https://blockstream.info/api/block-height/968100
curl -s https://mempool.space/api/block-height/968100
```

Both were queried independently before this was written and agreed.

### What this choice gives up, stated rather than glossed

A beacon exists so the finished parameters depend on a value **nobody could
predict while contributing**. This one is a block that **already exists**, so
contributors 2..N will know it. It was chosen this way deliberately.

What it still does, and what matters most in practice, is that it is **fixed
now, before any contribution, and published**. The failure this rules out is
the one that is actually reachable: taking "whatever the latest block is" at
finalisation time lets whoever decides *when* to finalise decide *which* block
— an adaptive choice made after seeing every contribution. Naming the height
in advance removes that entirely.

The stronger form is a **future** height, announced now, whose hash nobody can
compute yet. It costs only waiting, and it is what a redo should use if this
ceremony is ever re-run. It is not used here because the operator chose a
current height.

Note also what a beacon **never** does: its scalar is public, so it adds no
secrecy and does not rescue a ceremony whose participants all colluded. The
final `delta` is every contribution multiplied together with a value anyone
can compute. Security rests on one participant having destroyed their scalar.

## The circuit and the phase-1 string

| | |
|---|---|
| repository commit | `7ec052e0035f1cac7f2ad0ffd16f5d1d2d1e2933` |
| circuit | 18,107 constraints, 19 instance variables, QAP domain 2^15 |
| phase 1 | Zcash Sapling, slice sha256 `1bfd7acdb3ecbfaaa695ab159a7a643a2eb58203a4d93361040c6bd4c2aa3d6e` |
| inheriting | 87 attested human contributions and a public random beacon |

## Still open, and the operator's to decide

- **who the participants are.** At least one must be able to fail
  independently of the party deploying the pool, or "at least one was honest"
  reduces to "trust us";
- **whether an unattested contribution counts.** Contribution 1 is one, and
  says so;
- **who verifies afterwards**, from outside.

Procedure: `doc/shielded-pool-phase2-runbook.md`.
