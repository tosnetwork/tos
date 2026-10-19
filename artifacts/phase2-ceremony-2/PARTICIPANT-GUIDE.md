# Contributing to the ceremony, from a bare VPS

Every command on this page can be copied and pasted. It assumes a fresh
**Ubuntu 24.04** or **Debian 12** server and that you have never seen this
repository before.

You need about **25 minutes**, most of it waiting, and no prior knowledge of
the cryptography.

> **This guide describes ceremony 2.** Ceremony 1 was withdrawn — see
> [`../phase2/SUPERSEDED.md`](../phase2/SUPERSEDED.md). Do not follow any
> instructions inside `artifacts/phase2/`.

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
  your own VPS adds nothing to the trust set. Your contribution is recorded
  and counts for nothing on its own, because the property claimed is that
  *someone else* could not compel or observe you. Do it anyway — but the
  ceremony still needs an outsider.
- **Your signing key must be one that was already publicly yours**, or at
  least published and pinned in `roster.json` *before* the ceremony opened.
  Section 5 covers both cases.

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
cd tos
```

Now move to **the exact commit the announcement names**. Set and export
`ANNOUNCED_COMMIT` to the full commit value from the published `ANNOUNCEMENT.md`.

> Until the ceremony is announced that file is
> [`ANNOUNCEMENT.draft.md`](ANNOUNCEMENT.draft.md) and its commit field still
> reads `TO FIX`. If that is what you see, the ceremony has not opened and
> there is nothing to contribute to yet.

```sh
git checkout "$ANNOUNCED_COMMIT"
```

Check you are where you think you are:

```sh
git rev-parse HEAD
export TOS_ROOT="$PWD"
```

**The output must equal the announced commit, character for character.** If it
does not, stop and ask. Contributing from different code than everyone else is
not automatically an attack and is automatically worth stopping for.

---

## 4. Install Rust, at the version this repository pins

```sh
cd "$TOS_ROOT"
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

A signature is worth exactly what the identity behind it is worth. A key
created five minutes ago, signing a statement, proves only that somebody had a
keyboard.

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

Generate one **and then publish it**, before the ceremony opens:

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
the operator so it goes into `roster.json` **before the announcement is
published**.

A key added to the roster afterwards proves nothing — it cannot be shown not
to have been added to suit the contributions already made.

### 5c. PGP instead

If you would rather use a PGP key that is already yours, skip the above and
use `--sign-with "gpg:$SIGNING_KEY_ID"` in section 7. Give the operator your
40-character fingerprint and your exported public key.

---

### 5d. Pin the announced roster

Before contributing, obtain the public roster and the independently archived
announcement. Set `ROSTER` to your absolute path to that public roster file and
`ROSTER_SHA256` to the digest pinned by the announcement, not a digest supplied
with a newly substituted file. Run:

```sh
set -eu
printf '%s  %s\n' "$ROSTER_SHA256" "$ROSTER" | sha256sum -c -
```

Require success, then check your exact public key, signing principal/fingerprint
and independence declaration in that roster. Check its ceremony identifier and
protocol against the announcement too. Keep both files for the final audit;
`roster.template.json` with `TO FIX` entries is not a usable roster. A hash check
binds bytes, not the truth of the roster's independence claims.

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
`Display`, and its `Debug` prints a placeholder, so logging it is a compile
error rather than a leak.

**This is why the script builds from source instead of shipping you a
binary.** If you run a binary somebody handed you, the thing you are attesting
to is their honesty, which is exactly what your participation was meant to
remove.

---

### 6a. Prepare the machine before any contribution

Use a machine and operating environment you control, independently of the
project. Do not let the project administer it, observe its memory or supply a
prebuilt contributor. Before running section 7, in the same shell:

```sh
ulimit -c 0
ulimit -c
swapon --show
```

The core limit must print `0`; the swap listing must be empty. If not, stop
and use a suitable machine or arrange its configuration yourself before drawing
any randomness. Do not rely on turning swap off afterwards. Ensure there is no
hibernation, debugger, crash collector, memory capture, VM checkpoint or backup
that can preserve this process's memory. A zero core limit alone does not prove
that a privileged crash collector or hypervisor cannot copy memory.

Use an ephemeral VM only if its host and snapshot policy meet that requirement.
If you cannot establish it, disclose the limitation and do not claim destruction.
Section 11 covers disposal after the process exits. Keep the signing identity
available on your own signing machine for the later verification statement.

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

### 7a. Build the verifier and check the incoming transcript

Set `CEREMONY` to the absolute path of the public directory you just received.
Keep `TOS_ROOT` from section 3. Use the announced commit, with no local source
changes, and a shell without a `CARGO_TARGET_DIR` override. Build the binaries
explicitly: the contribution wrapper builds only `phase2-contribute`, not the
verifier used in section 8.

```sh
cd "$TOS_ROOT"
cargo build --release --locked --manifest-path tools/shielded-pool-ceremony/Cargo.toml --bins
export PHASE2_BIN="$TOS_ROOT/tools/shielded-pool-ceremony/target/release"
```

Read the public `ceremony.json`. Its phase-1 slice and starting-key digests must
match the announcement. If it already has participant entries, run:

```sh
"$PHASE2_BIN/phase2-verify" "$CEREMONY"
python3 "$TOS_ROOT/test/shielded-pool/verify-attestations.py" "$CEREMONY" \
    --roster "$ROSTER" \
    --attestations "$(dirname "$CEREMONY")" --in-progress
```

Both must exit 0. Expect **NOT FINISHED** from the first: no beacon may yet
have closed it. Check each existing attestation's `built from` field against
the announced commit yourself: the attestation verifier checks its format,
not equality with the announcement. It also does not establish publication
time, real independence or destruction of randomness.

For an empty starting transcript, `phase2-verify` deliberately refuses "no
contributions". Instead rebuild a separate, public starting directory locally:

```sh
CHECK_DIR=$(mktemp -d)
"$PHASE2_BIN/phase2-begin" "$CHECK_DIR/initial"
cmp "$CHECK_DIR/initial/key.bin" "$CEREMONY/key.bin"
cmp "$CHECK_DIR/initial/contributions.bin" "$CEREMONY/contributions.bin"
cmp "$CHECK_DIR/initial/ceremony.json" "$CEREMONY/ceremony.json"
```

Require all comparisons to succeed and the printed starting-key/transcript
hashes to equal the announcement. This scratch directory is a deterministic
opening-key check, not a participant contribution; do not submit it as a second
ceremony. Request the original tool-produced files if someone reformatted the
opening record. No signature check is possible before any contribution exists.

Before either route, independently compare the roster's SHA-256 with the
announcement, as in section 5d. Do not replace a failed check with a waiver or
contribute to see whether that fixes it. Complete section 6a first.

### 7b. Make your one contribution

Now contribute. **Note `$HOME` — do not write `~` here**, because the `~`
inside `ssh:~/...` is not expanded by the shell and the script will tell you
it cannot read your key:

```sh
cd "$TOS_ROOT"
./scripts/shielded-pool-phase2-contribute.sh "$CEREMONY" \
    --sign-with ssh:$HOME/.ssh/tos_signing_key
```

or, for PGP, set `SIGNING_KEY_ID` to the actual signing-key identifier:

```sh
cd "$TOS_ROOT"
./scripts/shielded-pool-phase2-contribute.sh "$CEREMONY" \
    --sign-with "gpg:$SIGNING_KEY_ID"
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
./scripts/shielded-pool-phase2-contribute.sh "$CEREMONY" \
    --sign-with ssh:$HOME/.ssh/tos_signing_key \
    --entropy-file ~/my-dice-rolls.txt
```

Your bytes are mixed *with* the system generator, never instead of it, so a
poor choice here cannot make the result worse than not using it.

---

## 8. Check your own work before you hand it on

```sh
cd "$TOS_ROOT/tools/shielded-pool-ceremony"
"$PHASE2_BIN/phase2-verify" "$CEREMONY"
```

About three minutes. It rebuilds the starting key, audits every contribution
including yours, and will say **NOT FINISHED** at the end — that is correct
and expected. The ceremony is not closed until the announced beacon block
exists.

Then check that your attestation matches the record and that your signature
verifies against the roster:

```sh
cd "$TOS_ROOT"
python3 test/shielded-pool/verify-attestations.py "$CEREMONY" \
    --roster "$ROSTER" \
    --attestations "$(dirname "$CEREMONY")" \
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
  yet. The ceremony should not be open. Ask the operator.
- *"no verified contribution comes from a participant declared independent"*
  — you forgot `--in-progress`.

---

## 9. Publish in your own public repository

Publish in **your own public GitHub repository**, outside the project's control,
before the contribution-close height. First complete section 11's destruction
procedure. The wrapper signs automatically; its signature does not prove erasure.
Publish only the public files: the updated `key.bin`, `contributions.bin`,
`ceremony.json`, your `attestation-N.txt` and its `.sig` or `.asc`.
The complete updated directory is required, not just one contribution record.

Set `PUBLIC_REPO` to a clean clone of your own public repository and `N` to your
actual contribution index. Select `SIGNATURE` as the exact `.sig` or `.asc` path
beside your attestation. Do not copy optional entropy files, keys or machine images.

```sh
set -eu
mkdir -p "$PUBLIC_REPO/contribution/ceremony"
cp "$CEREMONY/key.bin" "$CEREMONY/contributions.bin" "$CEREMONY/ceremony.json" \
    "$PUBLIC_REPO/contribution/ceremony/"
cp "$(dirname "$CEREMONY")/attestation-$N.txt" "$SIGNATURE" "$PUBLIC_REPO/contribution/"
cd "$PUBLIC_REPO/contribution"
sha256sum ceremony/key.bin ceremony/contributions.bin ceremony/ceremony.json \
    "attestation-$N.txt" "$(basename "$SIGNATURE")" > SHA256SUMS
cat SHA256SUMS
cd "$PUBLIC_REPO"
git add contribution
git commit -F contribution/SHA256SUMS
git push
```

Check the public commit URL and archive the publication time and observed
Bitcoin height. The commit message publishes the **whole-file** SHA-256 values;
the per-entry contribution digest inside the attestation is different. Commit
dates alone are author-controlled, so keep independently observable publication
evidence. Do not rewrite or delete this public record.

Ordinary Git files larger than **100 MiB** are blocked. Instead attach the public
files and `SHA256SUMS` as release assets in your own repository, and paste the
manifest into the release text. Each release asset must be **under 2 GiB**.
Check these [file limits](https://docs.github.com/en/repositories/working-with-files/managing-large-files/about-large-files-on-github)
and [release limits](https://docs.github.com/en/repositories/releasing-projects-on-github/about-releases)
before publication. Never substitute a pointer for the actual contribution bytes.
If these limits prevent publication, stop and agree a public archival plan before
contributing. The normal directory is about 6 MB.

## 10. Project fetch and handoff

Send the project your public repository's exact commit URL or release URL and
manifest. The project fetches those public files, independently reads the hashes
from your commit/release text, and checks them before importing. From the fetched
`contribution` directory:

```sh
sha256sum -c SHA256SUMS
```

Also compare the manifest itself with the values in the published commit/release
text; a downloaded manifest alone authenticates nothing. Any mismatch stops the
handoff. The project preserves your original bytes and signed attestation.
A private upload to the project does not replace your own public publication.

## 11. Destroy the randomness and dispose of the environment

Wait for the contributor to exit successfully. The source wipes its secret
scalar, its inverse and temporary entropy buffers; there is no scalar file to
publish or shred. Process exit and a successful audit do not independently prove
that every memory copy was destroyed.

Section 6a's no-swap/no-dump/no-snapshot precautions must have held **before and
throughout** the contribution. If an unexpected dump, swap write, checkpoint or
memory copy may exist, do not sign an unconditional destruction statement.
Disclose what happened and let the ceremony be refused or re-announced rather
than claiming secrecy you cannot establish.

If you used `--entropy-file`, discard that private input and its backups too;
never include it in the public archive. Keep only the public ceremony,
attestation and signature needed for sections 9–10. After exporting them, shut
down and discard the ephemeral VM and its snapshots/volumes on a host you
control, or sanitize the dedicated machine using its supported erase procedure.
Deleting files or a VM does not prove that SSD wear-levelled copies, provider
snapshots or backups disappeared. If you do not control those copies, state that
limit; do not promise their destruction. Nobody can verify this claim from the
transcript.

Keep your roster signing key available on your independently controlled signing
machine until you have signed the final verification statement in section 13.
Remove only a disposable working copy when appropriate, not the last copy of an
identity you still need. Never send a private key, scalar, entropy input, dump
or machine image to the project.

---

## 12. Independently verify after the beacon

On a machine you control, obtain the source independently again and follow
sections 2–4 and 7a's build commands at the announcement's exact commit. Do not
use the project's verifier binary or substitute a newer checkout silently.
Download the complete public ceremony and all attestations/signatures. Set:

- `CEREMONY`: absolute path of the final public ceremony directory;
- `ROSTER`: the roster archived with the original announcement;
- `ROSTER_SHA256`: its 64-character SHA-256 pinned in that announcement;
- `ATTESTATIONS`: directory containing every `attestation-N.txt` and signature;
- `PUBLIC_CHECKS`: a fresh output directory outside the source checkout;
- `CANDIDATE_VK` (optional): a provisional verifying key offered for comparison;
  final parameters must not be published until your signed independent PASS;
- `BEACON_HASH`: the block hash you read yourself at the announced beacon height.

Read the Bitcoin chain through your own network path, using your full node or
independent sources, not a response supplied by the project. Record the height,
hash, source and observation time. Resolve any disagreement or reorganisation
before claiming a result; do not switch heights or choose a convenient hash.
The beacon encoding is exactly 64 lowercase ASCII hexadecimal characters,
without a newline, not 32 decoded bytes. Repeat section 5d's roster check using
your archived announcement and roster before continuing. Check the beacon
independently:

```sh
set -eu
mkdir -p "$PUBLIC_CHECKS"
printf '%s' "$BEACON_HASH" | grep -Ex '[0-9a-f]{64}'
printf '%s' "$BEACON_HASH" > "$PUBLIC_CHECKS/expected-beacon.bin"
test "$(wc -c < "$PUBLIC_CHECKS/expected-beacon.bin")" -eq 64
cmp "$PUBLIC_CHECKS/expected-beacon.bin" "$CEREMONY/beacon.bin"
sha256sum "$PUBLIC_CHECKS/expected-beacon.bin" "$CEREMONY/beacon.bin"
```

Then run both verifiers, from the source root with `PHASE2_BIN` set by section 7a:

```sh
cd "$TOS_ROOT"
"$PHASE2_BIN/phase2-verify" "$CEREMONY" --vk-out "$PUBLIC_CHECKS/vk.bin" \
    > "$PUBLIC_CHECKS/transcript-verification.txt" 2>&1
cat "$PUBLIC_CHECKS/transcript-verification.txt"
grep -F 'This ceremony is finished:' "$PUBLIC_CHECKS/transcript-verification.txt"
test "$(wc -c < "$PUBLIC_CHECKS/vk.bin")" -eq 1248
python3 test/shielded-pool/verify-attestations.py "$CEREMONY" \
    --roster "$ROSTER" --attestations "$ATTESTATIONS" \
    > "$PUBLIC_CHECKS/attestation-verification.txt" 2>&1
cat "$PUBLIC_CHECKS/attestation-verification.txt"
if [ -n "${CANDIDATE_VK:-}" ]; then cmp "$PUBLIC_CHECKS/vk.bin" "$CANDIDATE_VK"; fi
sha256sum "$CEREMONY/key.bin" "$CEREMONY/contributions.bin" \
    "$CEREMONY/ceremony.json" "$CEREMONY/beacon.bin" "$PUBLIC_CHECKS/vk.bin"
```

Require exit 0 from every command and the explicit **finished** message.
`phase2-verify` also exits 0 for an unfinished but valid chain, so exit 0 alone
is insufficient. It rebuilds the starting key, audits all contributions,
checks every transcript link and recomputes the final beacon step. The
attestation verifier must name your pinned identity as independent and verify
all participant signatures; do not use `--in-progress` or `--unattested-ok` here.

Compare the announced opening digests, source commit in each attestation,
participant roster and published order yourself. Check that your exact
contribution/position was retained and that the final entry is the announced
beacon with no later participant. A valid signature or transcript does not prove
the announcement preceded contributions, that nobody contributed after close,
that a roster declaration is true, or that randomness was destroyed.

The final `vk.bin` is 1,248 public bytes for this circuit. Publish its full
SHA-256 and your independently derived transcript digest, not just "verified".
A successful transcript audit is not a deployment acceptance test; the project's
remaining gate is described in the [ceremony runbook](../../doc/shielded-pool-phase2-runbook.md#verification-by-people-who-did-not-run-it).

## 13. Sign and publish your independent verification statement

Write a separate public `verification.txt` in `PUBLIC_CHECKS`. State PASS or
REFUSED, the ceremony and announcement/archive identifiers, roster SHA-256,
announced source commit, observed close/beacon heights and beacon block hash,
the artifact/key SHA-256 values above, your contribution index/digests, command
exit statuses and the finished/not-finished result. Include observation sources
and times and disclose unresolved assumptions or failures. A PASS states that
you independently reproduced those bytes; it does not certify secret erasure.

Sign the final text with the **same roster-pinned identity**, on your own
signing machine. Set `SIGNING_KEY` to your existing private SSH key path, or
`SIGNING_KEY_ID` to your roster's actual GPG signing-key identifier:

```sh
REPORT="$PUBLIC_CHECKS/verification.txt"
ssh-keygen -Y sign -f "$SIGNING_KEY" -n file "$REPORT"
```

Or use GPG instead:

```sh
REPORT="$PUBLIC_CHECKS/verification.txt"
gpg --local-user "$SIGNING_KEY_ID" --clearsign --output "$REPORT.asc" "$REPORT"
```

Publish the text, `.sig` or `.asc`, and public verification outputs through the
announced reporting channel and **your own public GitHub repository**. Commit
the report, signature and outputs there (or attach release assets), publishing
their SHA-256 values in the commit/release text as in section 9. The project
must wait for your signed PASS before publishing final parameters. Its own
verification does not replace yours. Readers must check
this statement's signature using your key from the pinned roster. It is not a
contribution attestation and `verify-attestations.py` does not validate it;
that tool checks only `attestation-N.txt` files. Do not rename this report into
that format. Keep your contribution attestation unchanged.

If anything fails, publish a signed REFUSED statement with the exact failing
check, public hashes and observed discrepancy. Do not endorse parameters,
change the roster/beacon, waive signatures, create another contribution or
sign a success claim to help the project finish. Preserve public evidence and
report it using `<REPORTING_CHANNEL>`. Never include secret material.

---

## What happens next, and why nothing is finished yet

Contributions close when the Bitcoin chain reaches the height named in the
announcement. A strictly later beacon block — also named in advance, and not
yet mined — supplies the closing value. Only then is the ceremony
finalised, verified by people who did not run it, and the parameters frozen.

Until that point the parameters do not exist, and anybody who tells you
otherwise is describing a different ceremony.
