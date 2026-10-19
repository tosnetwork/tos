# Phase-2 ceremony 2 — final parameters published; not deployed

**Status: ceremony 2 is complete. The independent participant's signed PASS
has been verified and the project's own verification reproduces the same key
and transcript digest. Final ceremony parameters are published here.
The pool has not been deployed; the separate deployment acceptance gate remains
required.**

Read the immutable [announcement](https://github.com/tosnetwork/tos/blob/0fd773063b91833f287d435e82a60d4d2235f988/artifacts/phase2-ceremony-2/ANNOUNCEMENT.md)
and [publication observations](PUBLICATION.json). Contributions close at Bitcoin
height **972111**; beacon height is **972112**. The pinned source commit is
`66fb007e7d3d6b509c32ad1b3ce4af470d96a53c`. The [roster](roster.json) and
[beacon-finalized audit directory](ceremony/) are public inputs for the independent participant.
The participant publishes their handoff in their own public repository, as
required by [INDEPENDENT-PARTICIPANT.md](INDEPENDENT-PARTICIPANT.md).

Ceremony 1 is withdrawn — [`../phase2/SUPERSEDED.md`](../phase2/SUPERSEDED.md)
says why. Its directory is kept unedited, because editing a published
announcement is the thing this whole process exists to prevent.

## What has to happen before this opens

In this order. The order is the point: each step is only worth something if
the ones before it are already public.

| # | step | who | state |
|---|---|---|---|
| 1 | attestation verification exists and can fail | done | `test/shielded-pool/verify-attestations.py`, 19 cases, each watched to fail |
| 2 | recruit participants, at least one independent of the operator | **operator** | ffreeofmoney-bit, independent; owner confirmed |
| 3 | collect each participant's already-public signing key into `roster.json` | operator | pinned in roster.json |
| 4 | fix fresh beacon and closing heights | **operator** | close 972111; beacon 972112, fixed |
| 5 | publish the announcement, archive it, record where and when | operator | announcement commit 0fd773063; push completed 05:21:59 UTC |
| 6 | run `phase2-begin`, publish the starting digests | operator | public opening follows the announcement in a separate commit |
| 7 | contributions, in any order, each signed | participant | contribution 1 accepted; see participant-contribution-1/RECEIPT.json |
| 8 | close contributions at the close height; apply the later beacon; independent signed PASS before final publication | project and independent verifier | independent signed PASS and project verification passed; final parameters published |

## If you are going to contribute

**[`PARTICIPANT-GUIDE.md`](PARTICIPANT-GUIDE.md)** — every command, from an
empty VPS to a published attestation. It assumes you have never seen this
repository. Roughly 25 minutes, most of it waiting.

The external party who contributes once and then independently audits the
finished ceremony should start with
[`INDEPENDENT-PARTICIPANT.md`](INDEPENDENT-PARTICIPANT.md). It links to the guide's
commands and separates the contribution attestation from the final signed audit.

## What is in here

```
ANNOUNCEMENT.draft.md    the announcement, with every undecided field marked TO FIX
PARTICIPANT-GUIDE.md     contribution and final-verification commands, in one place
INDEPENDENT-PARTICIPANT.md  the external contributor/verifier's role and refusal rules
roster.template.json     the participant roster to fill in and pin
```

`roster.json`, `ceremony/`, `beacon.bin` and `attestation-N.txt` appear as the
steps above are taken. There is nowhere in any of them for a secret to go,
which is why they live in a public repository while the ceremony runs.

## Why there is a verifier before there is a ceremony

Contributions could be signed since the contribution script was written, and
**nothing anywhere verified a signature**. A ceremony with nine forged
attestations and one with nine genuine ones passed every check this
repository had, identically.

So step 1 came first this time. The verifier refuses a document naming a
contribution the chain does not contain, a valid document moved to another
position, a signature from a key nobody published, a genuine signature over
different bytes, a roster listing one key under two names, and a ceremony in
which no verified contribution comes from anyone independent of the operator.
Each of those is a test that has been watched to fail.

## Coordinator run sequence for 2026-10-19

This section keeps project commands beside the existing opening checklist;
there is no second runbook. The commands below are instructions for the test
lead. Steps A/B/C/D/E/F have now been executed; see `PUBLICATION.json`,
`participant-contribution-1/RECEIPT.json`, `BEACON-OBSERVATIONS.json`,
`FINAL-PUBLICATION.json` and their commits. This is the recorded run sequence;
do not repeat contribution or finalisation.
Do not rerun opening or alter the announced heights. No contribution secret
was generated on the coordinator. Today's target is
07:00 UTC / 16:00 JST. Bitcoin timing cannot guarantee it. If the beacon is
late, wait; never switch heights or use a mined substitute. If a contribution
misses close, abandon and announce a new ceremony, never extend this one.

Only the third party generates contribution secrets, on their own machine;
none belongs on the coordinator. `phase2-begin` builds a public deterministic
opening key from this checkout's committed `artifacts/phase1` slice. Its random
pairing-check weights are not a contribution secret. Beacon finalisation uses
public bytes. Keep all working output in a dedicated public-artifact directory,
not among private keys. Do not run a project contribution: today's roster can
contain just the one independent contributor. If another contributor is added,
that identity must be pinned before announcement and follow the same procedure.

### A. Prepare source and public inputs (flow 0)

From an independently obtained clean checkout of `agent/phase2-ceremony-2`,
record and pin its **full commit**, not a moving branch. Use the same commit
for the participant build. Run in a shell with no `CARGO_TARGET_DIR` override.
Set `WORK` to a fresh absolute directory outside the checkout; it holds public
files only. Set the remaining inputs to the external party's actual supplied
values, before running this SSH-key example. For a GPG key use the template's
GPG object with its actual signing fingerprint and inline public key instead;
never convert a GPG key into an SSH roster entry.

```sh
set -eu
export TOS_ROOT="$PWD"
export SOURCE_COMMIT="$(git rev-parse HEAD)"
test -z "$(git status --porcelain)"
export WORK="$(mktemp -d)"
export CEREMONY="$WORK/ceremony"
export ROSTER="$WORK/roster.json"
export PHASE2_BIN="$TOS_ROOT/tools/shielded-pool-ceremony/target/release"
cargo build --release --locked --manifest-path tools/shielded-pool-ceremony/Cargo.toml --bins
```

Supply `PARTICIPANT_NAME`, `SSH_PRINCIPAL`, `PUBLIC_KEY_FILE` (public key only),
`KEY_IDENTITY_URL`, `PARTICIPANT_REPOSITORY` (their public GitHub repository),
and `REPORTING_CHANNEL` as exported shell variables. Verify their identity and
control of that repository out of band. No private key is an input.

```sh
python3 - <<'PY'
import json, os
from pathlib import Path
key = Path(os.environ['PUBLIC_KEY_FILE']).read_text().strip()
if not key.startswith('ssh-') or len(key.split()) < 2:
    raise SystemExit('Expected a complete SSH public key')
participant = {
    'name': os.environ['PARTICIPANT_NAME'], 'affiliation': 'independent',
    'independent_of_operator': True,
    'key': {'type': 'ssh', 'principal': os.environ['SSH_PRINCIPAL'], 'public_key': key},
    'published_at': [os.environ['KEY_IDENTITY_URL']],
    'contribution_repository': os.environ['PARTICIPANT_REPOSITORY'],
}
roster = {'protocol': 'tos-shielded-pool-v1-phase2', 'ceremony': 'ceremony-2',
          'participants': [participant]}
Path(os.environ['ROSTER']).write_text(json.dumps(roster, indent=2) + '\n')
PY
sha256sum "$ROSTER"
```

The repository field is public handoff metadata; signature verification uses
only the key fields. Review the actual roster with the third party using
[guide section 5d](PARTICIPANT-GUIDE.md#5d-pin-the-announced-roster).
Do not publish a template or fictitious identity. The existing public-key
identity requirements in the announcement still apply.

### B. Derive fresh heights and fill the announcement (flow 1)

The following two independent HTTPS sources must agree on both height and hash.
These helpers only read Bitcoin data. Retry on disagreement or transport error;
do not choose whichever answer is convenient. All responses are bounded by
30 seconds. Preserve the outputs and UTC observation times in `WORK`.

```sh
bitcoin_tip() {
    h1=$(curl --fail --silent --show-error --max-time 30 https://blockstream.info/api/blocks/tip/height)
    h2=$(curl --fail --silent --show-error --max-time 30 https://mempool.space/api/blocks/tip/height)
    test "$h1" = "$h2" || return 1
    case "$h1" in ''|*[!0-9]*) return 1 ;; esac
    TIP=$h1
    a1=$(curl --fail --silent --show-error --max-time 30 "https://blockstream.info/api/block-height/$TIP")
    a2=$(curl --fail --silent --show-error --max-time 30 "https://mempool.space/api/block-height/$TIP")
    test "$a1" = "$a2" || return 1
    printf '%s' "$a1" | grep -Ex '[0-9a-f]{64}' >/dev/null || return 1
    TIP_HASH=$a1
}
bitcoin_tip
export ANCHOR_HEIGHT="$TIP" ANCHOR_HASH="$TIP_HASH"
export CONTRIBUTION_CLOSE_HEIGHT="$((TIP + 4))"
export BEACON_HEIGHT="$((CONTRIBUTION_CLOSE_HEIGHT + 1))"
export START_DATE="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
printf '%s anchor=%s hash=%s close=%s beacon=%s\n' "$START_DATE" \
    "$ANCHOR_HEIGHT" "$ANCHOR_HASH" "$CONTRIBUTION_CLOSE_HEIGHT" "$BEACON_HEIGHT" \
    > "$WORK/height-observations.txt"
cp "$TOS_ROOT/artifacts/phase2-ceremony-2/ANNOUNCEMENT.draft.md" "$WORK/ANNOUNCEMENT.md"
```

**Edit the copy, not a published announcement.** Replace the entire expired
section 1 schedule with the fresh observation above: anchor = current agreed
tip, close = anchor + 4, beacon = close + 1. Remove all old 2026-09-22 dates,
968,125 / 970,141 / 970,285 values, fourteen-day/144-block/2,016-block prose,
old anchor hash and claims those heights are confirmed. State the new one-block
gap and its actual limitations: this is a short schedule, not a guaranteed
wall-clock completion time or an absolute defence against privately mined blocks.
Keep the public-beacon secrecy limitation. Replace the closing height also in
section 7. Fill source commit with `SOURCE_COMMIT`, roster SHA-256 with the
hash just printed, actual participant/verifier identities and their repository,
`REPORTING_CHANNEL`, and the planned public publication location.
Keep the committed circuit/phase-1/opening digests unchanged; the native opening
in C below must reproduce them. Use the [independent participant flow](INDEPENDENT-PARTICIPANT.md)
as the contribution, publication and final-verification policy. Replace section
5's unrestricted handoff with the participant's own public-repository handoff.

No `TO FIX`, old height, expired date or placeholder may remain in the version
presented to the participant. Review the entire copy together, not just search
results. The publication record must show real URL, observed UTC time and tip,
and an independent archive/observation of the announcement alone. Do not invent
an archive URL in advance. The roster and announcement may be published together,
but no contribution or production ceremony directory may be in that publication.
Immediately before publication, run `bitcoin_tip` again and record it; require:

```sh
bitcoin_tip
test "$TIP" -lt "$CONTRIBUTION_CLOSE_HEIGHT"
test "$TIP" -lt "$BEACON_HEIGHT"
date -u '+%Y-%m-%dT%H:%M:%SZ'
printf 'publication-check tip=%s hash=%s\n' "$TIP" "$TIP_HASH"
```

If stale before publication, re-derive from the current agreed tip and re-review
all fields. **After publication nothing moves.** The test lead publishes the
announcement and roster alone, obtains the independent publication record,
then sends the fixed public URLs and SHA-256 to the third party for flow 2.
Record the actual public URL/time/tip and archive evidence without rewriting
the announced commitments. The external party must accept that precedence.

### C. Open the public directory, only after announcement (flows 2–3)

After the standalone announcement is externally observable, run:

```sh
"$PHASE2_BIN/phase2-begin" "$CEREMONY" > "$WORK/opening.txt" 2>&1
cat "$WORK/opening.txt"
python3 - <<'PY'
import json, os
from pathlib import Path
r = json.loads((Path(os.environ['CEREMONY']) / 'ceremony.json').read_text())
assert r['starting_key_sha256'] == '018853105392e4e0ef82ae59514f137b1f1a19892023b70b72ef58941b017c04'
assert r['transcript'] == '7dcfafe1626b5586d5713654c55cc0887590fd789c391ecf1e28bfaf93e66287'
assert r['phase1_slice_sha256'] == '1bfd7acdb3ecbfaaa695ab159a7a643a2eb58203a4d93361040c6bd4c2aa3d6e'
assert r['entries'] == []
PY
sha256sum "$CEREMONY/key.bin" "$CEREMONY/contributions.bin" "$CEREMONY/ceremony.json"
```

Stop on any mismatch. Publish the opening public files and output separately
from the already published announcement. The third party checks the opening,
contributes on their own machine, disposes of randomness and publishes their
signed handoff in their own repository. Use the commands in
[guide sections 7–11](PARTICIPANT-GUIDE.md#7-get-the-ceremony-directory-and-contribute);
do not run the contribution wrapper on the coordinator.

### D. Fetch their public handoff and check bytes (flows 4–5)

Set `CONTRIBUTION_COMMIT` to their full published commit and `N` to their
attestation index. For the ordinary Git-file route:

```sh
export FETCHED="$WORK/participant-publication"
git clone "$PARTICIPANT_REPOSITORY" "$FETCHED"
git -C "$FETCHED" checkout --detach "$CONTRIBUTION_COMMIT"
git -C "$FETCHED" show --no-patch --format=fuller HEAD
cd "$FETCHED/contribution"
cat SHA256SUMS
sha256sum -c SHA256SUMS
```

Independently compare every manifest entry to their public commit text, not just
the downloaded manifest. Require exactly the three ceremony files, attestation
and signature named in guide section 9; reject paths outside that directory.
For release assets download those exact public assets and apply the same checks
against the release text; preserve URLs and publication observations. Check that
the independent publication occurred before close. Then, still before close:

```sh
bitcoin_tip
test "$TIP" -lt "$CONTRIBUTION_CLOSE_HEIGHT"
cp "$FETCHED/contribution/ceremony/key.bin" "$CEREMONY/key.bin"
cp "$FETCHED/contribution/ceremony/contributions.bin" "$CEREMONY/contributions.bin"
cp "$FETCHED/contribution/ceremony/ceremony.json" "$CEREMONY/ceremony.json"
cp "$FETCHED/contribution/attestation-$N.txt" "$WORK/"
```

Set `SIGNATURE_NAME` to the exact accompanying `attestation-$N.txt.sig` or
`attestation-$N.txt.asc` filename and copy it too; no re-signing:

```sh
cp "$FETCHED/contribution/$SIGNATURE_NAME" "$WORK/"
```
Run [guide section 8](PARTICIPANT-GUIDE.md#8-check-your-own-work-before-you-hand-it-on)
against this directory with `ROSTER` pinned and attestations in `WORK`.
Check the announced source commit in each attestation manually. Preserve the
original pre-beacon files as public evidence. A failure stops finalisation.

### E. Apply the announced beacon, then request independent audit (flows 6–7)

Do not accept contributions at or after close. Wait until both sources can
serve the announced beacon block. A missing block or failed request means wait,
not a replacement beacon. Source disagreement/reorganisation means pause and
report; never silently choose another height or hash.

```sh
bitcoin_tip
test "$TIP" -ge "$BEACON_HEIGHT"
b1=$(curl --fail --silent --show-error --max-time 30 "https://blockstream.info/api/block-height/$BEACON_HEIGHT")
b2=$(curl --fail --silent --show-error --max-time 30 "https://mempool.space/api/block-height/$BEACON_HEIGHT")
test "$b1" = "$b2"
printf '%s' "$b1" | grep -Ex '[0-9a-f]{64}'
printf '%s' "$b1" > "$WORK/beacon-input.bin"
test "$(wc -c < "$WORK/beacon-input.bin")" -eq 64
date -u '+%Y-%m-%dT%H:%M:%SZ'
printf 'beacon height=%s hash=%s\n' "$BEACON_HEIGHT" "$b1"
"$PHASE2_BIN/phase2-finalise" "$CEREMONY" "$WORK/beacon-input.bin" \
    > "$WORK/finalisation.txt" 2>&1
cat "$WORK/finalisation.txt"
```

Preserve both source responses, URLs and UTC observation time. Publish the
beacon-finalized transcript, beacon bytes and all attestations as **audit input**;
do not label it the final parameter release yet. The third party independently
builds, reads Bitcoin and follows [guide sections 12–13](PARTICIPANT-GUIDE.md#12-independently-verify-after-the-beacon),
then publishes their signed PASS or REFUSED in their own repository.

### F. Verify the independent PASS, perform project checks and publish (flow 8)

Fetch the third party's report/signature/output from their exact public commit
or release, compare its published SHA-256 values, and check its signature with
the **original roster key**. For SSH, set `REPORT`, `REPORT_SIGNATURE`,
`SSH_PUBLIC_KEY_FILE` (the key extracted from the pinned roster), and use the
original `SSH_PRINCIPAL`:

```sh
printf '%s %s\n' "$SSH_PRINCIPAL" "$(cat "$SSH_PUBLIC_KEY_FILE")" > "$WORK/report-allowed-signers"
ssh-keygen -Y verify -f "$WORK/report-allowed-signers" -I "$SSH_PRINCIPAL" \
    -n file -s "$REPORT_SIGNATURE" < "$REPORT"
```

For GPG, set `GPG_PUBLIC_KEY_FILE` to the public key extracted from the pinned
roster, `GPG_FINGERPRINT` to its actual signing fingerprint, and `REPORT_SIGNATURE`
to the clearsigned `.asc` report. Use a fresh keyring:

```sh
export GNUPGHOME="$(mktemp -d)"
chmod 700 "$GNUPGHOME"
gpg --batch --import "$GPG_PUBLIC_KEY_FILE"
gpg --batch --status-fd 3 --output "$WORK/verified-report.txt" \
    --decrypt "$REPORT_SIGNATURE" 3> "$WORK/report-signature-status.txt"
awk -v expected="$GPG_FINGERPRINT" \
    '$1 == "[GNUPG:]" && $2 == "VALIDSIG" && toupper($3) == toupper(expected) { ok=1 } END { exit !ok }' \
    "$WORK/report-signature-status.txt"
cat "$WORK/verified-report.txt"
```

Require `VALIDSIG` to name the exact roster signing fingerprint (not merely
any imported key).
Review the signed text: it must explicitly PASS this exact finalized transcript,
beacon, roster, announced source and derived verifying-key hash. An unsigned,
ambiguous or REFUSED result blocks final publication. No project check replaces it.

Run project verification from the pinned source, after that independent PASS:

```sh
cd "$TOS_ROOT"
"$PHASE2_BIN/phase2-verify" "$CEREMONY" --vk-out "$WORK/vk.bin" \
    > "$WORK/project-transcript-verification.txt" 2>&1
cat "$WORK/project-transcript-verification.txt"
grep -F 'This ceremony is finished:' "$WORK/project-transcript-verification.txt"
test "$(wc -c < "$WORK/vk.bin")" -eq 1248
python3 test/shielded-pool/verify-attestations.py "$CEREMONY" \
    --roster "$ROSTER" --attestations "$WORK" \
    > "$WORK/project-attestation-verification.txt" 2>&1
cat "$WORK/project-attestation-verification.txt"
sha256sum "$WORK/vk.bin"
```

Compare that full verifying-key digest and all transcript hashes with the signed
independent PASS. Only then publish the final set: `key.bin` (proving parameters),
`vk.bin`, `contributions.bin`, `ceremony.json`, `beacon.bin`, original announcement
and pinned roster, every contribution attestation/signature, independent signed
verification and its public source URL, both parties' verification outputs,
publication/height observations and a complete SHA-256 manifest. Preserve the
third party's own public links. No secret material is in that set. Deployment
still requires the separate [acceptance gate](../../doc/shielded-pool-ceremony.md#the-acceptance-gate).

## Contribution 1 receipt

The [original participant publication](participant-contribution-1/) is preserved
byte for byte, with its original SHA256SUMS and signed attestation. The active
`ceremony/` directory now contains that verified extension. Both Bitcoin sources
still reported tip 972109 when the fetched files were observed and checked,
before close 972111. Historical push times supplied by the test lead and the
independent source observations are distinguished in
[RECEIPT.json](participant-contribution-1/RECEIPT.json).

`OPENING-SHA256SUMS` describes the immutable opening commit
`af64d98e629e3146f382da2aff9d74a9ec63d876`, not the subsequently extended active
`ceremony/` directory. The participant snapshot's SHA256SUMS describes the
pre-beacon contribution and remains unchanged after beacon application.

## Beacon application and confirmation readings

The beacon remains Bitcoin block **972112**, exactly as announced. The owner
required a later reading time: **confirmation depth 1**, meaning one block on top
and tip at least **972113 on both sources**. This changes neither the beacon
height nor the close height. It is two confirmations if the beacon block itself
is included in the count.

Beacon hash: `00000000000000000000bf99b64907555658528c8adf804c0adb61495df53345`.
First seen from mempool.space at **2026-10-19 06:34:39 UTC**; the subsequent
two-source readings and every observed hash remained identical.

| Source | UTC reading interval immediately before finalisation | Tip | Blocks on top | Beacon hash |
| --- | --- | --- | --- | --- |
| https://blockstream.info/api | 2026-10-19T06:46:59.393654+00:00 to 2026-10-19T06:47:00.825954+00:00 | 972113 | 1 | `00000000000000000000bf99b64907555658528c8adf804c0adb61495df53345` |
| https://mempool.space/api | 2026-10-19T06:47:00.826102+00:00 to 2026-10-19T06:47:00.911503+00:00 | 972113 | 1 | `00000000000000000000bf99b64907555658528c8adf804c0adb61495df53345` |

Both sources also reported block 972113 with the beacon hash as its previous
block, establishing the required block on top. The post-finalisation readings
again agreed with the first-seen hash. No reorganisation was observed.
See [BEACON-OBSERVATIONS.json](BEACON-OBSERVATIONS.json) for all reading times,
confirmation depths, native execution times and artifact hashes, and
[BEACON-FINALISATION.txt](BEACON-FINALISATION.txt) for the native audit output.

The participant independently verified the complete `ceremony/` directory
(including `beacon.bin`), the original pinned roster and contribution attestation,
using the announced source commit and their own Bitcoin observations. The
[guide sections 12–13](PARTICIPANT-GUIDE.md#12-independently-verify-after-the-beacon)
remain the command reference. Their signed result is public in their own
repository and preserved below. The original participant files remain unchanged
in `participant-contribution-1/`. The project then completed step F; its own
verification did not substitute for the independent signed PASS.

## Final publication — 2026-10-19

The independent participant published their [signed complete verification PASS](https://github.com/ffreeofmoney-bit/tos-phase2-ceremony-2/commit/c8542cfd89dd22b7ca952851eda4c77a5839a6ec).
The exact report, detached signature, original manifest and participant-derived
verifying key are preserved in
[independent-verification/](independent-verification/). The pinned roster's SSH
key verifies the report under namespace `file`; a one-byte report alteration
fails verification. The owner supplied the
[verbatim independence confirmation](OWNER-INDEPENDENCE-CONFIRMATION.md).

Only after checking that PASS did the project independently verify the finalized
transcript at commit `adfbd0fd6b95cab92e21c747ac10d970368f9742` and derive the
public verifying key. Both derivations are byte-identical and match the required
digests:

| Item | Value |
| --- | --- |
| Verifying key | [vk.bin](vk.bin), 1,248 bytes |
| Verifying-key SHA-256 | `49696f52f361817869f68c3ba68d0d5a854737a4133ae4616255ac4a3846778c` |
| Final transcript digest | `03e67eb4b1cff48c9bc5952992a46d37ae0c32d6ba2f76910f785daca8704579` |
| Complete transcript and proving parameters | [ceremony/](ceremony/) |
| Pinned roster | [roster.json](roster.json) |
| Contribution attestation and signature | [attestation-1.txt](attestation-1.txt), [signature](attestation-1.txt.sig) |
| Independent signed report | [PASS](independent-verification/independent-verification-PASS.txt), [signature](independent-verification/independent-verification-PASS.txt.sig) |
| Project mathematical verification | [PROJECT-TRANSCRIPT-VERIFICATION.txt](PROJECT-TRANSCRIPT-VERIFICATION.txt) |
| Project strict signature verification | [PROJECT-ATTESTATION-VERIFICATION.txt](PROJECT-ATTESTATION-VERIFICATION.txt) |
| Publication record | [FINAL-PUBLICATION.json](FINAL-PUBLICATION.json) |
| Complete directory SHA-256 inventory | [FINAL-SHA256SUMS](FINAL-SHA256SUMS) |

`ceremony/key.bin` is the public proving key; no contribution randomness or
private signing key is published. The original standalone announcement, roster,
opening observations, participant handoff and beacon observations are retained.
Run `sha256sum -c FINAL-SHA256SUMS` from this directory to verify every local
publication file. Historical opening and pre-beacon manifests describe their
respective immutable snapshots.

### External raw verification archive

The canonical [verification-evidence.zip](https://raw.githubusercontent.com/ffreeofmoney-bit/tos-phase2-ceremony-2/c8542cfd89dd22b7ca952851eda4c77a5839a6ec/verification-evidence.zip)
is in the participant's repository at commit
`c8542cfd89dd22b7ca952851eda4c77a5839a6ec`:

- SHA-256: `f256555805a19eacf0a53140d17ad5de04e68e7ba5ba8e1e3819ef47c88f7442`.
- Size: **7,431,838 bytes**.
- Retention: no scheduled expiry; retain that archive and exact commit for the
  lifetime of these parameters. Availability is controlled by the participant.

The archive is referenced rather than present in the current project tree. Its
previous copy remains in project commit
`de94be8750d3d12a126b83cf40657e8fdf567899` deliberately: the commit history is
public timing evidence for announcement, contribution and beacon precedence,
so rewriting it is not acceptable.

`independent-verification/VERIFICATION-SHA256SUMS` is the participant's original,
unchanged manifest and includes the external archive. To check that complete
source publication, download the archive into a temporary directory alongside
copies of the retained report, signature, verifying key and original manifest,
then run `sha256sum -c VERIFICATION-SHA256SUMS` there. The local
`FINAL-SHA256SUMS` excludes the absent archive and instead pins the metadata
containing its canonical URL, digest, size and retention note. Downloaded raw
archives should remain outside the project checkout.

**No deployment or merge to main is part of this publication.** Ceremony
verification is complete, but the [deployment acceptance gate](../../doc/shielded-pool-ceremony.md#the-acceptance-gate)
is separate and remains required before deployment.
