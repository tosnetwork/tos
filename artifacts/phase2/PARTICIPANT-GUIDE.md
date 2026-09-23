# Contributing to the ceremony, from a bare VPS

Every command on this page can be copied and pasted. It assumes a fresh
**Ubuntu 24.04** or **Debian 12** server and that you have never seen this
repository before.

You need about **25 minutes**, most of it waiting, and no prior knowledge of
the cryptography.

> An earlier ceremony was withdrawn and its directory removed;
> [`README.md`](README.md) says what was wrong with it. If you are holding
> older instructions from somewhere else, discard them — this directory is
> the ceremony.

---

## 0. What you are actually doing

You will generate one random number, use it to re-randomise a cryptographic
parameter file, and then destroy it. Then you sign a short public statement
saying you destroyed it.

The parameters being built let people transact privately on TOS. **If
anybody who contributes genuinely destroys their random number, the system is
sound — even if everyone else cheated.** That is why the number of
participants matters less than their independence, and why your statement is
the valuable part: it is what lets a stranger conclude somebody can be asked.

You never see the random number. The software is written so that printing it
does not compile.

### Two things this guide cannot give you

- **If you are the operator** (the person deploying the pool), running this on
  your own VPS is a valid contribution, but does not add an independent
  participant. You can contribute first; an outside contribution remains a
  condition of final acceptance, not a condition of opening.
- **Existing and newly generated signing keys are both accepted.** Publish
  the public key under your identity and register it before your contribution
  is accepted. The register remains open during the contribution window.

---

## 1. The machine

| | |
|---|---|
| OS | Ubuntu 24.04 / Debian 12 (others work; only the `apt` lines change) |
| RAM | **1 GB is enough.** Measured peak across every step: 255 MB |
| disk | **5 GB free.** Roughly 310 MB git download, 860 MB checkout, 280 MB build output, 800 MB Rust toolchain |
| CPU | 2 cores is fine |
| network | outbound HTTPS only. Nothing listens |

Measured on two cores of a server CPU: build 14 s, and each of the three long
steps about 2½–3 minutes. **A budget VPS core is slower — allow 10–15 minutes
of waiting in total** and do not be alarmed by a step that appears to hang;
they print nothing for minutes at a time.

Everything that touches this machine is public. There is nowhere in the
ceremony directory for a secret to go, which is why it lives in a public
repository while the ceremony runs.

---

## 2. Install what is needed

```sh
sudo apt-get update
sudo apt-get install -y git build-essential curl python3 openssh-client gnupg ca-certificates
```

`build-essential` is needed because one dependency compiles C. The rest is
git, Python for the verifier, and the two signing tools.

---

## 3. Get the code

```sh
cd ~
git clone https://github.com/tosnetwork/tos.git
cd ~/tos
```

Now move to **the exact commit the announcement names**. Replace
`<ANNOUNCED_COMMIT>` with the value from `ANNOUNCEMENT.md` in this directory.

> Until the ceremony is announced that file is
> [`ANNOUNCEMENT.draft.md`](ANNOUNCEMENT.draft.md) and its commit field still
> reads `TO FIX`. If that is what you see, the ceremony has not opened and
> there is nothing to contribute to yet.

```sh
git checkout <ANNOUNCED_COMMIT>
```

If an announced commit was replaced by the privacy-only history rewrite,
first verify the signed [commit mapping](PRIVACY-PROVENANCE.json) using
tosman's registered public key, then check out its mapped revision. The
[cleanup record](PRIVACY-CLEANUP.md) explains why the cryptographic sources
and ceremony artifacts are unchanged. Use the mapped revision for the
comparison below and record the revision you actually built in your own
attestation. This exception permits metadata cleanup, not arbitrary code
changes.

Check you are where you think you are:

```sh
git rev-parse HEAD
```

**The output must equal the announced commit, character for character.** If it
does not, stop and ask. Contributing from different code than everyone else is
not automatically an attack and is automatically worth stopping for.

---

## 4. Install Rust, at the version this repository pins

```sh
cd ~/tos
./scripts/install-rust-toolchain.sh
```

Then make it available in this shell:

```sh
. "$HOME/.cargo/env"
rustc --version
```

The version printed should be `1.97.1`. The script pins both rustup and the
toolchain by checksum, so this is not "whatever Rust was newest today".

---

## 5. Your signing identity

A signature binds a statement to a key. Publishing that key under your
account links it to your claimed identity; it does not prove independence or
secret destruction. There is no minimum key age.

### 5a. If you already have a published SSH key (the easy case)

Most people do — the one on your GitHub account. Anyone can see it at
`https://github.com/<your-username>.keys`. Copy that key file onto this VPS
(from *your laptop*, not from the server):

```sh
# run this on YOUR OWN COMPUTER, not on the VPS
scp ~/.ssh/id_ed25519 user@your-vps:/home/user/.ssh/tos_signing_key
```

Then on the VPS:

```sh
chmod 600 ~/.ssh/tos_signing_key
```

> **Never run `cat ~/.ssh/tos_signing_key`.** That prints your private key.
> The public half — the safe half — is what ends in `.pub`.

### 5b. If you have no published key

Generate one **and then publish it**, before your contribution is accepted:

```sh
ssh-keygen -t ed25519 -f ~/.ssh/tos_signing_key -C "your-name-or-handle"
```

It will ask for a passphrase. Either is fine; see the warning in section 7 if
you set one.

Print the **public** half — this one is safe to show anyone:

```sh
cat ~/.ssh/tos_signing_key.pub
```

Now make it publicly yours: add it to your GitHub account under
**Settings → SSH and GPG keys**, so it appears at
`https://github.com/<your-username>.keys`. Send that URL and the key line to
the operator so it goes into `roster.json`. A public repository record or your
own website can also publish the key; adding it as a GitHub authentication
key is optional. New participants may register while the ceremony is open.
Each accepted contribution records the register revision used to verify it;
existing accepted identities and keys must not be silently replaced.

### 5c. PGP instead

If you would rather use an existing or new PGP key, skip the above and
use `--sign-with gpg:<your-key-id>` in section 7. Give the operator your
40-character fingerprint and your exported public key.

---

## 6. Read the two files you are being asked to trust

This is not ceremony: it is the only step that makes your contribution mean
anything. About 280 lines total.

```sh
less ~/tos/tools/shielded-pool-ceremony/src/secret.rs
less ~/tos/tools/shielded-pool-ceremony/src/entropy.rs
```

(press `q` to quit)

They are the whole of the discipline: the random number is drawn from
`/dev/urandom` inside the contributor, used, and wiped. It is never returned,
never written to a file, and cannot be printed — the type holding it has no
`Display`, and its `Debug` prints a placeholder. Ordinary formatting does not
compile; debug formatting emits only the placeholder.

**This is why the script builds from source instead of shipping you a
binary.** If you run a binary somebody handed you, the thing you are attesting
to is their honesty, which is exactly what your participation was meant to
remove.

---

## 7. Get the ceremony directory, and contribute

The operator sends you a directory of about **6 MB**. It contains no secret.
Put it at `~/ceremony`:

```sh
cd ~
tar xzf ceremony.tar.gz        # if you were sent an archive
ls ~/ceremony
```

You should see `key.bin`, `contributions.bin` and `ceremony.json`.

Now contribute. **Note `$HOME` — do not write `~` here**, because the `~`
inside `ssh:~/...` is not expanded by the shell and the script will tell you
it cannot read your key:

```sh
cd ~/tos
./scripts/shielded-pool-phase2-contribute.sh ~/ceremony \
    --sign-with ssh:$HOME/.ssh/tos_signing_key
```

or, for PGP:

```sh
cd ~/tos
./scripts/shielded-pool-phase2-contribute.sh ~/ceremony \
    --sign-with gpg:<your-key-id>
```

It builds first (under a minute), then runs for **about three minutes**,
printing almost nothing. Most of that time is spent rebuilding the starting
key from scratch so that you *check* it rather than trust it.

### If it stops and seems to hang

If your key has a passphrase, `ssh-keygen` asks for it. In an ordinary
interactive SSH session you will see the prompt. **If you run this under
`nohup`, in a cron job, or with input redirected, the prompt goes nowhere and
the command waits forever** — it will sit there indefinitely rather than fail.
Run it in a normal interactive shell.

### If it refuses to start

- *"this checkout has uncommitted changes"* — you edited something. Run
  `git status` to see what, and `git checkout .` to discard it.
- *"cannot read ssh key"* — you used `~` instead of `$HOME`.

### Optional: add your own randomness

If you do not want to rely solely on the kernel's generator, you can stir in
bytes of your own — dice rolls, a hardware source, anything:

```sh
./scripts/shielded-pool-phase2-contribute.sh ~/ceremony \
    --sign-with ssh:$HOME/.ssh/tos_signing_key \
    --entropy-file ~/my-dice-rolls.txt
```

Your bytes are mixed *with* the system generator, never instead of it, so a
poor choice here cannot make the result worse than not using it.

---

## 8. Check your own work before you hand it on

```sh
cd ~/tos/tools/shielded-pool-ceremony
./target/release/phase2-verify ~/ceremony
```

About three minutes. It rebuilds the starting key, audits every contribution
including yours, and will say **NOT FINISHED** at the end — that is correct
and expected. The ceremony is not closed until the announced beacon block
exists.

Then check that your attestation matches the record and that your signature
verifies against the roster:

```sh
cd ~/tos
python3 test/shielded-pool/verify-attestations.py ~/ceremony \
    --roster artifacts/phase2/roster.json \
    --attestations ~ \
    --in-progress
```

It prints one line per contribution naming who signed it. Yours should say
your name, and whether you are recorded as independent of the operator.

**`--in-progress` matters here.** Without it the tool also enforces the rule
that the finished ceremony must contain at least one verified contribution
from someone independent of the operator. That is a property of the *closed*
ceremony, so while contributions are still coming in it can be legitimately
unsatisfied — and being told "this ceremony rests on nobody" when you have
just done everything correctly is alarming and not your fault. With the flag
it is reported rather than refused. Everything that *is* your responsibility
still refuses.

**If it refuses, do not hand the directory on.** Send the refusal message to
the operator — it is written to say exactly which rule failed.

Two refusals that are not your fault:

- *"the roster could not be read"* — `roster.json` has not been published
  yet or you have the wrong revision. Obtain the published register before
  handing on your contribution.
- *"no verified contribution comes from a participant declared independent"*
  — you forgot `--in-progress`.

---

## 9. Publish your attestation

Your attestation is at `~/attestation-<N>.txt`, with its signature beside it
as `~/attestation-<N>.txt.sig` (or `.asc` for PGP). Both are public. Look at
them:

```sh
cat ~/attestation-*.txt
```

**Publish the text and the signature somewhere that is visibly yours** — a
GitHub gist under your account, a comment on the ceremony's issue, your own
website, a post from an account people know is you. This is the step that
turns your contribution from an anonymous entry in a file into something a
stranger can trace to a person who can be asked.

Then send both files to the operator.

---

## 10. Send the ceremony directory onward

```sh
cd ~
tar czf ceremony-after-me.tar.gz ceremony attestation-*.txt attestation-*.txt.sig
ls -lh ceremony-after-me.tar.gz
```

(drop the `.sig` from that line if you signed with PGP; use `.asc`)

Send it back however you like — it is about 6 MB, it carries no secret, and
any transport will do. From **your own computer**:

```sh
scp user@your-vps:/home/user/ceremony-after-me.tar.gz .
```

If you would rather open a pull request, fork the repository, copy the
directory into `artifacts/phase2/`, and push. Neither route is more
trustworthy than the other: what makes the result checkable is the published
attestation, not how the bytes travelled.

---

## 11. What is left on this machine

Nothing holds your random number. It existed only in the contributor's memory
and was wiped; there is no file to shred.

Two honest caveats, because "nothing is left" is easy to say and harder to
guarantee:

- **Swap.** If this VPS has swap enabled, memory pages *can* in principle
  reach disk. Check with `swapon --show`. If it prints nothing, there is no
  swap and nothing to worry about.
- **The provider's snapshots.** You do not control your hypervisor's memory.
  This is a limit of using a VPS at all, not of this software.

If you want to be thorough, destroy the VPS when you are done. It has served
its purpose and nothing on it is needed again.

Your signing key is the one thing worth keeping or deliberately removing:

```sh
shred -u ~/.ssh/tos_signing_key        # only if you generated it for this
```

Do **not** do that if you copied in a key you use for anything else.

---

## What happens next, and why nothing is finished yet

Contributions close when the Bitcoin chain reaches the height named in the
announcement. The block **after** that — also named in advance, and not yet
mined by anyone — supplies the closing value. Only then is the ceremony
finalised, verified by people who did not run it, and the parameters frozen.

Until that point the parameters do not exist, and anybody who tells you
otherwise is describing a different ceremony.
