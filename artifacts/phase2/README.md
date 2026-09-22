# Phase-2 ceremony, in progress

**Open. Announced. One contribution. Not closed, and not yet trustworthy.**

Procedure: `doc/shielded-pool-phase2-runbook.md`.
Announcement: [`ANNOUNCEMENT.md`](ANNOUNCEMENT.md) — published before
contribution 1, and nothing in it changes.

## Where it stands

| | |
|---|---|
| starting key | `018853105392e4e0ef82ae59514f137b1f1a19892023b70b72ef58941b017c04` |
| opening transcript | `7dcfafe1626b5586d5713654c55cc0887590fd789c391ecf1e28bfaf93e66287` |
| beacon | Bitcoin block 968100, `00000000000000000000ff8d74…` — fixed in the announcement, **applied only at the close** |
| contributions | 1 |
| transcript now | `41949b6ffdc08d0d2361353e23f7b4298e0bf9c4518b69cd39013f8b2b77d0cf` |

| # | who | contribution | attestation |
|---|---|---|---|
| 1 | an automated agent on the operator's machine | `12cb397274285 3d0…` | `attestation-1.txt`, **unsigned** |

**This ceremony currently rests on nobody.** Contribution 1 adds nothing to
the trust set beyond the operator's own — the agent cannot see the scalar, but
the trust boundary is the machine and the machine is the operator's. It starts
being worth something at contribution 2.

## If you are contribution 2

You need: a checkout at the commit named in `attestation-1.txt`, your own
machine, and a signing key that was already publicly yours.

Read these two files first — about 280 lines, and the whole of what protects
your scalar:

- `tools/shielded-pool-ceremony/src/secret.rs`
- `tools/shielded-pool-ceremony/src/entropy.rs`

Then:

```sh
./scripts/shielded-pool-phase2-contribute.sh artifacts/phase2/ceremony \
    --sign-with gpg:<your-key-id>          # or ssh:<your-key-file>
```

It builds from source rather than running a binary somebody handed you, which
is the point rather than an inconvenience: your contribution is worth
something only if the scalar was destroyed, and that is a property of source
you can read. It takes about two minutes, almost all of it rebuilding the
starting key so that you check it rather than trust it. It refuses to run on a
dirty checkout.

Publish your attestation, commit the updated directory, and hand it on.

## Closing it, when the participants are done

```sh
target/release/phase2-finalise artifacts/phase2/ceremony artifacts/phase2/beacon.bin
```

`beacon.bin` holds the 64 ASCII hex characters of the announced block hash,
no newline, sha256 `067b5b03a57f8d844b944b85d20217e75fed9f12e47238462322520c49338308`.
`phase2-verify` recomputes the closing step from those bytes and refuses
anything that is not what they determine.

## Then, before anything is deployed

Verification by people who did not run it, each publishing the verifying key's
SHA-256. Two parties who never spoke reproducing the same digest from the same
record is the strongest thing this process produces — it is a computation, so
it either reproduces or it does not, and it does not depend on either of them
being trustworthy.

## What is in here

```
ANNOUNCEMENT.md             published before contribution 1; nothing in it changes
beacon.bin                  the announced block hash, applied at the close
ceremony/key.bin            the proving key as it stands  (~6 MB, replaced each step)
ceremony/contributions.bin  every contribution, 672 bytes each, in order
ceremony/ceremony.json      what each step was, and the digests
attestation-N.txt           what participant N says they did
```

**There is nowhere in any of it for a secret to go**, which is why it is in a
public repository while the ceremony is still running.
