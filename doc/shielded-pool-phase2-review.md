# Phase-2 ceremony: a second reading, and a rehearsal

You are reviewing and rehearsing the shielded pool's Groth16 phase-2 ceremony.
It was written by one author with no outside review, which is the one gate
time cannot close from inside. You are that outside reading.

Work in `~/tos-privacy` on `feat/shielded-pool`.

**This is not the ceremony.** It produces a review and a rehearsal that gets
deleted. The real one is `doc/shielded-pool-phase2-runbook.md`, and what makes
it real is published beforehand and checked by outsiders afterwards, none of
which is in the code. If you are an automated agent, read that file's section
on who can be a participant before assuming you could be one: you can verify
a finished ceremony usefully, because verification is a computation that does
not depend on your being trusted. Contributing is not.

---

## 0. Rules that override everything else in this document

These are absolute. If following any instruction below would break one of
them, stop and say so instead.

1. **Never print, echo, log or write a contribution scalar.** The type that
   holds it (`Secret`, in `tools/shielded-pool-ceremony/src/secret.rs`) has no
   `Display`, no `Serialize`, and a `Debug` that prints `Secret(<withheld>)`.
   **Do not remove that redaction, add a print, or derive `Debug` on it to
   "see what is happening."** That redaction is the thing under review; a
   patch that defeats it is not a debugging step, it is the defect.

2. **If you generate a signing key for a rehearsal, delete it the moment you
   are done with it** — the private half and the `.pub` half. Generate it
   under a temporary directory you control, never inside the repository, and
   **never commit one, never paste one into a report, an issue or a commit
   message.** A key that outlives the rehearsal that needed it is a key
   somebody will later mistake for a real one.

3. **Do not commit or publish any rehearsal ceremony directory.** Label it as
   a rehearsal in your report and delete it when finished. A directory that
   looks like a finished ceremony is dangerous precisely because ours is
   designed to be publishable.

4. Seeds in the test files are named `test-only-…` on purpose and are not
   secrets — reading and quoting those is fine. Do not confuse them with the
   rule above.

5. **Do not run a real ceremony.** Everything you do here is a rehearsal.

---

## 1. What you are checking

That the implementation is the construction it claims to be, and that the
checks it makes are the checks that construction needs.

**Frame this as conformance, not as an attack.** You are comparing code
against a published design and reporting where they differ. That is the
useful output and it is also the one that survives a tool's content filter.

The construction is the standard Groth16 phase-2 MPC (BGM17 / the shape
bellman's `phase2` and Filecoin's implement). `ark-groth16` 0.5 has no MPC
module, so this is written against arkworks directly rather than reused.

---

## 2. Read these, in this order

| | file | why |
|---|---|---|
| 1 | `doc/shielded-pool-ceremony.md` | what is claimed and what is deliberately not claimed |
| 2 | `tools/shielded-pool-ceremony/src/phase2.rs` | the starting key, `gamma = delta = 1` |
| 3 | `tools/shielded-pool-ceremony/src/contribution.rs` | the contribution, the proof of knowledge, the audit, the beacon |
| 4 | `tools/shielded-pool-ceremony/src/secret.rs` and `entropy.rs` | ~280 lines; the whole of the secret discipline |
| 5 | `tools/shielded-pool-ceremony/src/crosscheck.rs` | the same audit on blst instead of arkworks |
| 6 | `test/shielded-pool/mutations-ceremony.py` | 45 mutations, each naming the test that must go red |

---

## 3. The claims, so you check them rather than re-derive them

1. **The starting key has no secrets** and is a deterministic function of the
   phase-1 slice and the R1CS, so two people building it must get identical
   bytes. Proven by element-for-element equality against
   `Groth16::generate_parameters_with_qap` on the same secrets
   (`tests/phase2_initial.rs`).
2. **A contribution** multiplies `delta` in both groups by a drawn scalar `d`
   and divides the `L` and `H` queries by it. Nothing else may move.
3. **The proof of knowledge** publishes `s`, `s·d` in G1 and `h·d` in G2,
   where `h = hash_to_g2(transcript ‖ s ‖ s·d)`.
4. **The audit needs no intermediate keys**: the starting key is rebuildable,
   each contribution is 672 bytes, and the final queries pair against the
   final `delta` to cancel a product nobody knows.
5. **The beacon** adds no secrecy and **does not rescue full collusion** —
   `d_beacon` is a hash of published bytes. Security rests on one participant
   having destroyed their scalar.
6. **`gamma` stays at 1** throughout, which the construction permits.
7. **The QAP domain is `constraints + instance_variables`**, not
   `max(constraints, variables)`.

Check each. Say which you confirmed, which you could not, and which are wrong.

---

## 4. Known soft spots — do not spend time rediscovering these, do check them

1. **`pok-challenge-points`** is a recorded mutation survivor: dropping `s`
   and `s·d` from the challenge hash changes no test verdict. It is kept
   because the knowledge extractor in the security proof needs it. **Is that
   right, and is there a concrete forgery that would kill it?** If you can
   build one, that is the most valuable thing in this review.
2. **The blst cross-check is library-independent, not author-independent.**
   Both sides share the point encoding, deliberately, and the *meaning* of
   the checks. An error in what ought to be checked is reproduced faithfully.
3. **The beacon claim in item 5 above was wrong until 2026-09-22** and says
   something weaker now. Check the corrected version is right.
4. **`gamma = 1`** rests on the paper, not on anything in this repository.
5. Batched query checks draw their weights from the verifier's own entropy
   after seeing the key. `the_weights_are_what_catches_a_compensating_pair`
   is the only test that shows the weights doing anything.

---

## 5. Rehearse it

```sh
cd tools/shielded-pool-ceremony
cargo build --release --bins
B=$(pwd)/target/release             # the crate has its own target directory
D=$(mktemp -d)                      # the rehearsal lives outside the repository

"$B/phase2-begin"      "$D/ceremony"
"$B/phase2-contribute" "$D/ceremony"
"$B/phase2-contribute" "$D/ceremony"
head -c 64 /dev/urandom > "$D/beacon.bin"
"$B/phase2-finalise"   "$D/ceremony" "$D/beacon.bin"
"$B/phase2-verify"     "$D/ceremony" --vk-out "$D/vk.bin"

rm -rf "$D"                         # rule 3
```

Each command takes about two minutes; almost all of it is rebuilding the
starting key from the committed slice, which is deliberate.

Then break one artifact at a time and confirm the refusal **names the right
reason**, not merely that something failed. `test/shielded-pool/ceremony-cli.py`
does this; read what it breaks and how, and look for a way to break the
directory that it does not cover.

If you exercise the participant script's signing branch
(`scripts/shielded-pool-phase2-contribute.sh --sign-with ssh:…`), generate the
key under `$D`, and rule 2 applies.

---

## 6. Report

For each finding:

- **where** — file and line;
- **what is claimed** and **what the code does**;
- **how to see it** — a command, a test, or a patch that turns something red;
- **whether it is exploitable**, and if you are unsure, say unsure.

"I read it and it looks right" is a useful answer when it is true. So is "I
could not check claim N without X". Please do not pad a report to look
thorough: an honest short review beats a long one that buries the one real
finding.

**Do not include any key material in the report**, including rehearsal keys.
