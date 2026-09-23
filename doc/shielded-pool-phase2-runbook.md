# Running the phase-2 ceremony for real

`doc/shielded-pool-ceremony.md` says what the machinery does and how to invoke
it. This says what turns invoking it into a ceremony.

The difference is not technical. The same four commands, run the same way,
produce parameters worth trusting or parameters worth nothing, and what
decides which is **what was published before the first contribution and who
checked afterwards**. None of that is in the code, and none of it can be.

---

## What makes it formal

Publish the rules before opening, then accept signed contributions. Final
acceptance follows verification; opening does not require a complete list of
participants or preselected outside verifiers.

1. **Announced before it opens.** The circuit, the phase-1 slice, the starting
   key's digest and the beacon are public *before* anyone contributes. A
   detail decided after contributions began cannot be shown not to have been
   chosen to suit them.
2. **Published as it runs.** Each contribution's digests and the contributor's
   signed statement go out as they happen, not in a bundle at the end.
3. **Verified by people who did not run it.** By someone outside the team,
   reproducing the digests from the published record. This is a final
   acceptance condition; verifiers need not be named before opening.

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
with a public identity-to-key binding. New signing keys are allowed.

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
| registration | open during the contribution window; append participants as they join | published policy |
| verification | anyone may verify; outside results required before final acceptance | published policy |

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

### The height must not have been mined

Naming a height in advance removes the adaptive choice at closing time —
whoever decides *when* to finalise no longer decides *which* block. That is
the smaller half.

The larger half is that **contributors must not be able to read the beacon
while contributing**, and a height that already exists gives it to all of
them. Ceremony 1 named a block that was already six deep, said so in its own
announcement, and was withdrawn for it.

So: announce a height that has not been reached, and **express the closing
deadline in blocks too** — contributions close when the chain reaches some
height strictly below the beacon's, by a margin of a day or so. The height gap is a schedule, not a cryptographic guarantee of
unpredictability. Retain independently observable publication evidence for
the closed pre-beacon transcript and each accepted contribution. A calendar deadline
has to be trusted, and a fast stretch of mining can move the beacon inside the
contribution window with nobody noticing.

If the participants are not done by the closing height, **re-announce; do not
extend**. Extending after seeing which contributions arrived is the same
adaptive choice, performed at the other end.

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

Existing and newly generated signing keys are accepted. Publish the public
key under the participant's identity, then add it to the append-only
`roster.json` register before accepting the contribution. Record the register
revision and SHA-256 with each accepted contribution. Registration remains
open until the contribution deadline; no complete advance list is required.
Previously accepted identities and keys must not be silently rewritten.

The contribution script uses the supplied key. `verify-attestations.py`
checks signatures against inline registered keys; it does not enforce key
age, publication time or register history. Those facts are recorded publicly.

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

python3 test/shielded-pool/verify-attestations.py /path/to/ceremony \
    --roster /path/to/roster.json

TOS_ROOT=<a checkout with a built func/fift> \
cargo run --release --manifest-path tools/shielded-pool-circuit/crosscheck/Cargo.toml \
    --example ceremony-gate -- /path/to/ceremony
```

The first rebuilds the starting key from the committed slice, audits every
contribution, recomputes the beacon step and emits the 1,248 bytes. The third
deploys a pool carrying exactly those bytes and requires it to accept a real
private transfer.

**The second is not optional, and it is the one that was missing.** The first
and third are arithmetic, and arithmetic is identical whoever performed it: a
ceremony run entirely by one person under nine invented names passes both. The
second checks that each attestation names the contribution the chain actually
contains, that its signature verifies under a registered key, and that at
least one verified participant is declared
independent of the operator. It refuses a ceremony that has none.

Signature checking is `ssh-keygen -Y verify` and `gpg --verify`, run as
subprocesses against a keyring built only from the roster — never the
verifier's own, or "did it verify" would depend on whose machine ran it.

**What each verifier publishes is the verifying key's SHA-256.** Two people
who never spoke reproducing the same digest from the same record is the
strongest thing this process produces — it is a computation, so it either
reproduces or it does not, and it does not depend on either of them being
trustworthy.

This is work an automated agent can do usefully, because nothing about it
requires the agent to be trusted. An agent can also execute a contribution on the operator's behalf. That
contribution is valid but shares the operator's failure modes and must not be
counted as an independent participant.

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
- **a beacon height that was already mined when it was announced**, so every
  contributor could read it;
- **a contribution accepted after the announced closing height**, or a closing
  deadline extended rather than the ceremony re-announced;
- a previously accepted identity or signing key silently replaced in the
  register, or an accepted contribution removed from the published chain;
- every participant under one party's control;
- participants who published nothing, so nobody can be asked;
- a participant who ran a binary somebody handed them rather than building
  from the announced commit;
- verification done only by the people who ran it.

The record proves the arithmetic. It cannot prove any of the above, which is
why they are written down here instead.

`verify-attestations.py` checks signature validity, record binding, key
uniqueness and declared independence. It cannot establish actual independence,
secret destruction, publication timing or register history. Keep the public
evidence needed to review those claims separately.
