# Phase-2 ceremony 2 — announcement (DRAFT, not yet published)

**This file is a draft. It is not an announcement until every field marked
`TO FIX` carries a value, it has been published where people outside this
repository can see it, and the publication record below is filled in. Until
then no contribution may be taken, and `phase2-begin` must not be run against
a directory intended for production.**

Ceremony 1 is withdrawn; see [`../phase2/SUPERSEDED.md`](../phase2/SUPERSEDED.md)
for what was wrong with it. Nothing from it carries forward except the
tooling, the circuit and the phase-1 slice.

---

## 1. The beacon — a block that does not exist yet

This is the field ceremony 1 got wrong, so it is first.

| | |
|---|---|
| source | **Bitcoin**, the block at height **970,285** |
| its hash | **does not exist.** That is the point |
| bytes that will be used | the 64 lowercase ASCII hex characters of that block's hash, exactly, no newline |
| witnesses | `blockstream.info` and `mempool.space`, independently, plus any full node |

### Why this height, derived rather than picked

| | height | how it is obtained |
|---|---|---|
| announcement anchor | 968,125 | the chain tip when this was written |
| **contributions close** | **970,141** | anchor + 2,016 — fourteen days of blocks at 144/day |
| **beacon** | **970,285** | close + 144 — one further day of blocks |

The anchor block's hash is
`0000000000000000000069c13457832a58fd579fe3d654ce239a5a5a8b54400f`,
read independently from both witnesses on 2026-09-22 and identical from each.
It is included for one reason: it proves this document was written **after**
that block existed. A document naming a future height is only worth something
if it can also be shown not to have been written later, and the pair of bounds
— written after 968,125, all contributions in before 970,141 — is what gives
it that.

### The property this buys, stated exactly

**Contributions close when the chain reaches height 970,141. The beacon is the
block 144 further on.** So the beacon's hash cannot be computed by anyone,
including the operator, until 144 blocks after the last contribution was
accepted.

This is a *structural* guarantee, not a probabilistic one, and that is why the
deadline is expressed in blocks rather than in wall-clock time. Blocks arrive
one at a time in an order everyone can see; "before the chain reached
970,141" is a fact an outside auditor can check against the record's own
timestamps and the published contributions. A calendar deadline would have to
be trusted, and a fast fortnight of mining could have moved the beacon inside
the contribution window without anyone noticing.

### These two heights are confirmed; the anchor decays

The operator confirmed 970,141 and 970,285 on 2026-09-22, when the tip was
968,125. Both are absolute heights and neither moves.

**What decays is the fourteen days.** They are measured from the anchor, not
from publication, so every day this stays unpublished is a day taken off the
contribution window rather than added to the end. If publication slips far
enough that the window is no longer long enough to recruit and collect
contributions, **re-derive both heights from a fresh anchor and re-confirm** —
do not publish this with the old numbers and hope. A window that expires with
contributions outstanding forces the ceremony to be abandoned and re-announced,
which costs everyone more than re-deriving two integers now.

### The deadline cannot be extended

If the participants are not finished when the chain reaches 970,141, **this
ceremony is abandoned and re-announced**, with a new anchor and a new height.
It is not extended. Extending a deadline after seeing which contributions
arrived is the same adaptive choice the beacon exists to remove, performed on
the other end. Fourteen days is chosen to make this unlikely, not to make it
impossible — if it happens, it costs everyone a second two minutes.

### What a beacon still does not do

Its scalar is public. It adds no secrecy, and it **does not rescue a ceremony
whose participants all colluded** — the final `delta` is every contribution
multiplied together with a value anyone can compute. Security rests on one
participant having destroyed their scalar. The beacon only ensures nobody
could aim at a `delta` prepared in advance.

---

## 2. The circuit and the phase-1 string

| | |
|---|---|
| repository commit | `TO FIX — the commit this is published at` |
| circuit | 18,107 constraints, 19 instance variables, QAP domain 2^15 |
| phase 1 | Zcash Sapling, slice sha256 `1bfd7acdb3ecbfaaa695ab159a7a643a2eb58203a4d93361040c6bd4c2aa3d6e` |
| inheriting | 87 attested human contributions and a public random beacon |
| starting key sha256 | `018853105392e4e0ef82ae59514f137b1f1a19892023b70b72ef58941b017c04` |
| opening transcript | `7dcfafe1626b5586d5713654c55cc0887590fd789c391ecf1e28bfaf93e66287` |

The starting key is a function of the circuit and the slice, so it is the same
value ceremony 1 published — that is a property of the construction, not
anything carried over. Every participant rebuilds it before contributing and
must get this digest; anyone who does not is contributing to something other
than this circuit and should stop.

---

## 3. The participants, fixed before this opens

The roster is [`roster.json`](roster.json), sha256 `TO FIX`.

**The roster is pinned by this announcement and does not change afterwards.**
A participant added after contributions began cannot be shown not to have been
added because of what the earlier contributions were.

| | |
|---|---|
| participants | `TO FIX — names, affiliations, and the public key each will sign with` |
| at least one independent of the operator | `TO FIX — required; the ceremony is refused without it` |
| verifiers | `TO FIX — who checks afterwards, from outside` |

Each participant's key must be one that was **already publicly theirs** before
this ceremony — a GitHub SSH key, a published PGP key, a key on a personal
domain. The roster carries the key material inline rather than a fingerprint,
so verification does not depend on fetching anything.
`test/shielded-pool/verify-attestations.py` refuses a roster that carries a
fingerprint alone, a roster that lists one key under two names, and a ceremony
in which no verified contribution comes from someone declared independent of
the operator.

### What counts as independent

Two participants who cannot fail independently are one participant. Two people
at the same company on the same machine image, or two agents on one operator's
laptop, are one. An automated agent running on the operator's machine is the
operator, and its contribution is recorded as such and counts for nothing —
that is not modesty, it is the definition of the property being claimed.

---

## 4. Publication record

**`TO FIX` — filled in when this is published, before contribution 1.**

| | |
|---|---|
| published at | `TO FIX — URL` |
| published on | `TO FIX — date and time, UTC` |
| chain tip at publication | `TO FIX — height and hash, from both witnesses` |
| archived copy | `TO FIX — an archive.org or equivalent snapshot URL` |

Ceremony 1's announcement and its first contribution went out in the same
push, minutes apart, so "announced first" could only be asserted by the party
who wrote both. The archive snapshot exists to make this one checkable by
someone who does not trust this repository's history.

---

## 5. How to take part

Read `doc/shielded-pool-phase2-runbook.md`. In short: from a clean checkout at
the commit above, on your own machine,

```sh
./scripts/shielded-pool-phase2-contribute.sh <ceremony-dir> \
    --sign-with ssh:<your-key-file>        # or gpg:<your-key-id>
```

It builds from source rather than running a binary somebody handed you, which
is the point rather than an inconvenience: your contribution is worth
something only if the scalar was destroyed, and that is a property of source
you can read. Two files, about 280 lines, are the whole of that discipline:

- `tools/shielded-pool-ceremony/src/secret.rs`
- `tools/shielded-pool-ceremony/src/entropy.rs`

Your scalar is drawn inside the contributor, used, and wiped. It is never a
return value, never written to a file, and cannot be printed — the type
holding it has no `Display` and its `Debug` prints a placeholder, so logging
it does not compile.

Publish your attestation. Then hand the directory on: it is about 6 MB, it
carries no secret, and any transport will do.

---

## 6. What will be checked afterwards, by people who did not run it

```sh
target/release/phase2-verify <ceremony-dir> --vk-out vk.bin
python3 test/shielded-pool/verify-attestations.py <ceremony-dir> \
    --roster artifacts/phase2-ceremony-2/roster.json
```

The first audits the mathematics and emits the 1,248 bytes. The second checks
that a person stands behind each contribution — that each attestation names
the contribution the chain actually contains, that its signature verifies
under a key on the roster above, and that at least one verified participant is
independent of the operator.

**What each verifier publishes is the verifying key's SHA-256.** Two people
who never spoke reproducing the same digest from the same record is the
strongest thing this process produces: it is a computation, so it either
reproduces or it does not, and it does not depend on either of them being
trustworthy.

---

## 7. What would invalidate this ceremony

Each of these turns it back into a rehearsal, and **none of them is detectable
from the artifacts afterwards** — which is why they are written down before it
opens:

- any contribution accepted after the chain reached height 970,141;
- the beacon height changed, for any reason, after this is published;
- the roster changed after this is published;
- every participant under one party's control;
- a participant signing with a key created for this ceremony;
- the deadline extended rather than the ceremony re-announced.
