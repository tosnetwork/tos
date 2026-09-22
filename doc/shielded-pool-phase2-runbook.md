# Running the phase-2 ceremony for real

`doc/shielded-pool-ceremony.md` says what the machinery does and how to invoke
it. This says what turns invoking it into a ceremony.

The difference is not technical. The same four commands, run the same way,
produce parameters worth trusting or parameters worth nothing, and what
decides which is **what was published before the first contribution and who
checked afterwards**. None of that is in the code, and none of it can be.

---

## What makes it formal

Three things, in this order. A ceremony missing any of them is a rehearsal
that produced a file.

1. **Announced before it opens.** The circuit, the phase-1 slice, the starting
   key's digest and the beacon are public *before* anyone contributes. A
   detail decided after contributions began cannot be shown not to have been
   chosen to suit them.
2. **Published as it runs.** Each contribution's digests and the contributor's
   signed statement go out as they happen, not in a bundle at the end.
3. **Verified by people who did not run it.** By someone outside the team,
   reproducing the digests from the published record.

---

## Who can be a participant

One honest participant is enough — that is the whole security argument — and
that makes "who counts as one" the only question that matters.

**Two participants who cannot fail independently are one participant.** Two
people at the same company on the same machine image, or two agents on one
operator's laptop, are one. This is not pedantry: the property is that at
least one scalar was destroyed by someone the others could not compel or
observe, and shared control removes exactly that.

So:

- **at least one participant from outside the organisation deploying the
  pool.** Without this, "at least one was honest" reduces to "trust us", and a
  ceremony that reduces to that produced nothing a sceptic can use;
- diversity of organisation, jurisdiction, hardware and operating system
  matters more than headcount;
- **there is no reason to cap the number.** A contribution costs one
  participant about two minutes and moves about 6 MB. The projects that ran
  small ceremonies did so because their circuits made each contribution
  expensive; ours does not.

A suggested shape, not a rule: three at the very least, seven to ten as a
target, at least one outside the team, everybody publishing an attestation
from an identity that was already publicly theirs.

For comparison, the phase-1 slice this deployment inherits — Zcash Sapling —
carries 87 attested human contributions. **Phase 1's trust surface is already
wide; phase 2's is only as wide as the people you find.**

---

## Before it opens: the announcement

Publish all of this, and do not change any of it afterwards.

| | what | where it comes from |
|---|---|---|
| circuit | the commit the ceremony is run at | `git rev-parse HEAD` |
| phase 1 | which published ceremony, and the slice's SHA-256 | `artifacts/phase1/*.json` |
| starting key | its SHA-256 | printed by `phase2-begin` |
| transcript | the opening digest | printed by `phase2-begin` |
| **beacon** | **the source, the exact height or round, and who will witness it** | your decision |
| participants | who, if the list is fixed in advance | your decision |
| verifiers | who will check afterwards | your decision |

### The beacon is the one that cannot be fixed later

Its scalar is public, so it adds no secrecy, and it **does not rescue a
ceremony whose participants all colluded** — the final `delta` is every
contribution multiplied together with a value anyone can compute. What it adds
is that the finished parameters depend on something nobody could predict while
contributing, so no participant could steer `delta` toward something prepared
in advance.

That property is entirely about **when** the beacon was named. A beacon chosen
after the contributions are in is decoration, and **no program can tell the
two apart** — `phase2-verify` recomputes the step from the bytes and confirms
it is that beacon's, which says nothing about when those bytes were chosen.

So it has to be announced first, publicly, in a form that cannot be quietly
reinterpreted: not "a Bitcoin block hash around the end of the month" but a
named source, a named height, and a named witness.

---

## Opening it

```sh
cd tools/shielded-pool-ceremony && cargo build --release --bins
target/release/phase2-begin /path/to/ceremony
```

Publish the two digests it prints. Every participant rebuilds the starting key
from the committed slice and must get the first of them; anyone who does not
is contributing to something other than this circuit, and should stop.

---

## Each participant

On their own machine, from a checkout at the announced commit:

```sh
./scripts/shielded-pool-phase2-contribute.sh /path/to/ceremony \
    --sign-with gpg:<their-key-id>        # or ssh:<their-key-file>
```

The script builds from source rather than running a supplied binary, which is
the point: a contribution is worth something only if the scalar was destroyed,
and that is a property of source the participant can read.

They publish the attestation. Then the directory — about 6 MB, carrying no
secret — goes to the next participant by any means at all.

**A participant who does not publish an attestation is not in the trust set.**
They appear in the record, and nothing ties the record to a person who can be
asked. Decide before opening whether such a contribution is acceptable.

---

## Closing it

At the announced moment, with the announced beacon's bytes:

```sh
target/release/phase2-finalise /path/to/ceremony beacon.bin
```

Publish the beacon's digest and the source it came from, so anyone can fetch
those bytes themselves and confirm they are the announced ones.

---

## Verification, by people who did not run it

This is the step that makes the rest mean something, and it is the one most
easily skipped because by then the file exists and looks finished.

Each verifier, independently:

```sh
target/release/phase2-verify /path/to/ceremony --vk-out vk.bin

TOS_ROOT=<a checkout with a built func/fift> \
cargo run --release --manifest-path tools/shielded-pool-circuit/crosscheck/Cargo.toml \
    --example ceremony-gate -- /path/to/ceremony
```

The first rebuilds the starting key from the committed slice, audits every
contribution, recomputes the beacon step and emits the 1,248 bytes. The second
deploys a pool carrying exactly those bytes and requires it to accept a real
private transfer.

**What each verifier publishes is the verifying key's SHA-256.** Two people
who never spoke reproducing the same digest from the same record is the
strongest thing this process produces — it is a computation, so it either
reproduces or it does not, and it does not depend on either of them being
trustworthy.

This is work an automated agent can do usefully, because nothing about it
requires the agent to be trusted. Contributing is not: an agent on an
operator's machine shares that operator's failure modes and adds nothing to
the trust set.

---

## The freeze

```sh
cargo run --manifest-path tools/shielded-pool-genesis/Cargo.toml --bin genesis -- \
    . out/manifest.json --verifying-key vk.bin
```

The key is part of the genesis state, so it fixes the state hash and therefore
the deployment address. **No address can be published before this point**, and
after it the ceremony cannot be redone without changing where the pool lives.

Publish the whole ceremony directory. It was designed to be publishable from
the moment it existed: there is nowhere in it for a secret to go.

---

## What invalidates it

Each of these turns a ceremony back into a rehearsal, and none of them is
detectable from the artifacts afterwards:

- the beacon named, or its height chosen, after contributions began;
- every participant under one party's control;
- participants who published nothing, so nobody can be asked;
- a participant who ran a binary somebody handed them rather than building
  from the announced commit;
- verification done only by the people who ran it.

The record proves the arithmetic. It cannot prove any of the above, which is
why they are written down here instead.
