#!/usr/bin/env python3
"""Who actually stands behind each contribution in a phase-2 ceremony.

`phase2-verify` audits the mathematics: the chain links, every proof of
knowledge holds, the beacon step recomputes. It can say all of that about a
ceremony run entirely by one person under nine invented names, because the
arithmetic of a contribution is identical whoever made it. The security
argument is not arithmetic -- it is that **at least one participant destroyed
a scalar without the others being able to compel or observe them** -- and the
signed statements provide accountability, not proof of secret destruction or
independence. Newly generated signing keys are permitted.

This checks those statements. It is the half that was missing: contributions
could be signed since the script was written, and nothing anywhere verified a
signature, so a ceremony with nine forged attestations and one with nine
genuine ones passed every check this repository had. That is an instrument
that answers by staying silent.

Three things are checked per contribution, and the first is the one a human
reader cannot do reliably:

1. **the document says what the chain says.** Digests are copied by hand into
   prose; a document naming a contribution that is not in the record, or
   naming the right contribution at the wrong index, is refused. This is
   pure comparison and needs no trust;
2. **the signature verifies**, using `ssh-keygen -Y verify` or `gpg --verify`
   -- the canonical verifiers, run as subprocesses. A signature parser
   written here could accept something they would reject, and a home-made
   parser that is wrong in the permissive direction is worse than no check;
3. **the signer is on the published participant register.** Registration is
   open during the contribution window, and new signing keys are allowed.
   Each accepted contribution publishes the register revision used to verify
   it. Public key material is inline; verification uses a throwaway keyring,
   never the operator's personal keyring. This tool does not verify publication
   times or the append-only history of the register.

A signature is only as good as the identity behind it, so the register entry
is also reported: whether it carries **public identity evidence** -- somewhere
outside this repository where a reader can see that the key is that person's.
An entry without it passes every other check exactly as a well-evidenced one
does, because a name, a boolean and a parseable key are all the other checks
look at. That is reported rather than refused: it is a weakness in an entry,
not a broken ceremony, and the ceremony this tool guards currently has one.
Refusing would be the wrong instrument; staying silent was the wrong one too,
and staying silent is what it did until a contributor wrote the absence into
their own attestation because no tool would.

And one property of the ceremony as a whole:

4. **at least one verified participant is independent of the operator.**
   Without it "at least one was honest" reduces to "trust us". The roster
   declares independence; this tool cannot check the claim, only that one was
   made and that the person making it signed.

Exit status is 0 only if every rule passes. Refusals name the rule.

    verify-attestations.py <ceremony-dir> --roster <roster.json> \
        [--attestations <dir>] [--unattested-ok <index>,...]

`--unattested-ok` waives rule 2 and 3 for named indices, loudly and in the
output, because a ceremony may deliberately include a contribution nobody
stands behind. It never waives rule 1, and it never waives rule 4.

`--in-progress` reports rule 4 rather than enforcing it, for a participant
checking their own work halfway through. Rule 4 is a property of the finished
ceremony: the first contributor to run this would otherwise be told the
ceremony rests on nobody -- true, expected, and not their fault. A refusal
that arrives when nothing is wrong teaches people to ignore refusals, which
costs more than the rule buys. Rules 1 to 3 still bite, because those *are*
their fault, and the final gate is run without this flag.
"""

import argparse
import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

PROTOCOL = "tos-shielded-pool-v1-phase2"
HEX64 = re.compile(r"\A[0-9a-f]{64}\Z")
HEX40 = re.compile(r"\A[0-9a-f]{40}\Z")


class Refused(Exception):
    """A rule failed. The message is the reason, and is the whole output."""


# --------------------------------------------------------------------------
# the roster


def load_roster(path: Path) -> dict:
    """The roster, held to a shape before anything trusts a field in it."""
    try:
        roster = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise Refused(f"the roster could not be read: {exc}") from exc

    if roster.get("protocol") != PROTOCOL:
        raise Refused(
            f"the roster is for protocol {roster.get('protocol')!r}, not {PROTOCOL!r}"
        )
    participants = roster.get("participants")
    if not isinstance(participants, list) or not participants:
        raise Refused("the roster lists no participants")

    seen_names = set()
    # Key material, by participant, so that two entries sharing one key are
    # caught here rather than at signature time.
    #
    # `ssh-keygen -Y find-principals` reports only the first principal whose
    # key matches, so a roster listing one key under two names verifies
    # happily and silently attributes both contributions to whichever name
    # came first -- two participants who are arithmetically one, counted as
    # two. The roster is where that is visible, and it is visible without
    # looking at a single signature.
    seen_keys = {}
    seen_principals = {}
    for who in participants:
        name = who.get("name")
        if not name:
            raise Refused("a roster entry has no name")
        if name in seen_names:
            raise Refused(f"the roster names {name!r} twice")
        seen_names.add(name)
        if "independent_of_operator" not in who:
            raise Refused(
                f"the roster does not say whether {name!r} is independent of the "
                "operator, and that is the question the roster exists to answer"
            )
        if not isinstance(who["independent_of_operator"], bool):
            raise Refused(
                f"{name!r}'s independent_of_operator must be a JSON boolean, not "
                f"{type(who['independent_of_operator']).__name__}"
            )
        key = who.get("key")
        if not isinstance(key, dict):
            raise Refused(f"{name!r} has no key")
        if key.get("type") == "ssh":
            principal = key.get("principal")
            if not principal:
                raise Refused(f"{name!r} has an ssh key with no principal")
            if principal in seen_principals:
                raise Refused(
                    f"the roster uses the principal {principal!r} for both "
                    f"{seen_principals[principal]!r} and {name!r}"
                )
            seen_principals[principal] = name
            material = str(key.get("public_key", ""))
            if not material.startswith("ssh-"):
                raise Refused(
                    f"{name!r}'s public_key is not an openssh public key. The roster "
                    "carries key material, not a fingerprint: a fingerprint makes the "
                    "verifier fetch the key from somewhere, and that fetch is then the "
                    "weakest thing in the chain"
                )
            # Type and base64 only: the trailing comment is free text and two
            # copies of one key with different comments are still one key.
            fields = material.split()
            identity = (fields[0], fields[1]) if len(fields) >= 2 else (material,)
        elif key.get("type") == "gpg":
            material = str(key.get("public_key", ""))
            if not material.startswith("-----BEGIN PGP"):
                raise Refused(f"{name!r}'s public_key is not an ascii-armoured pgp key")
            # The fingerprint is what a signature is attributed by, so a roster
            # entry without one can be verified against but never attributed.
            if not re.fullmatch(r"[0-9A-Fa-f]{40}", str(key.get("fingerprint", ""))):
                raise Refused(
                    f"{name!r} has a pgp key with no 40-character fingerprint; a "
                    "signature is attributed by fingerprint, so without it the key can "
                    "be verified against but the signer cannot be named"
                )
            identity = ("gpg", str(key["fingerprint"]).upper())
        else:
            raise Refused(f"{name!r} has key type {key.get('type')!r}; expected ssh or gpg")

        if identity in seen_keys:
            raise Refused(
                f"the roster lists one key under two names, {seen_keys[identity]!r} and "
                f"{name!r}. Two participants sharing a key are one participant, and the "
                "whole property being claimed is that one of them could not compel or "
                "observe the others"
            )
        seen_keys[identity] = name
    return roster


# --------------------------------------------------------------------------
# the document


FIELD = re.compile(r"^\s{2,}(built from|starting key|contribution|transcript)\s+(\S+)\s*$")
HEADER = re.compile(r"^TOS shielded pool, phase 2 -- contribution (\d+)\s*$")


def read_document(path: Path, index: int) -> dict:
    """The labelled digests out of an attestation, and nothing else.

    Parsed by label rather than by position so a participant may add prose --
    they are being asked to say something in their own words, and a template
    they cannot touch collects signatures on a sentence nobody read.
    """
    text = path.read_text()
    lines = text.splitlines()
    if not lines or not HEADER.match(lines[0]):
        raise Refused(
            f"{path.name} does not open with the contribution header; its first line is "
            f"{(lines[0] if lines else '')!r}"
        )
    stated_index = int(HEADER.match(lines[0]).group(1))
    if stated_index != index:
        raise Refused(
            f"{path.name} says it is contribution {stated_index}. A document renamed to "
            "another position is the cheapest possible forgery"
        )

    fields = {}
    for line in lines:
        found = FIELD.match(line)
        if found:
            label, value = found.group(1), found.group(2)
            if label in fields and fields[label] != value:
                raise Refused(f"{path.name} states two different values for {label!r}")
            fields[label] = value
    missing = {"built from", "contribution", "transcript"} - fields.keys()
    if missing:
        raise Refused(f"{path.name} does not state {', '.join(sorted(missing))}")
    return fields


def check_against_record(path: Path, fields: dict, entry: dict, record: dict) -> None:
    """The document's digests, against the chain the record actually contains."""
    if not HEX40.match(fields["built from"]):
        raise Refused(f"{path.name}: 'built from' is not a commit id: {fields['built from']!r}")
    for label in ("contribution", "transcript"):
        if not HEX64.match(fields[label]):
            raise Refused(f"{path.name}: {label!r} is not a SHA-256 digest: {fields[label]!r}")

    if fields["contribution"] != entry["sha256"]:
        raise Refused(
            f"{path.name} attests to contribution {fields['contribution'][:16]} and the "
            f"record's entry {entry['index']} is {entry['sha256'][:16]}"
        )
    if fields["transcript"] != entry["transcript_after"]:
        raise Refused(
            f"{path.name} states transcript {fields['transcript'][:16]} and the record's "
            f"entry {entry['index']} leaves the transcript at {entry['transcript_after'][:16]}"
        )
    stated_start = fields.get("starting key")
    if stated_start is not None and stated_start != record["starting_key_sha256"]:
        raise Refused(
            f"{path.name} says the ceremony started from {stated_start[:16]} and this one "
            f"started from {record['starting_key_sha256'][:16]}"
        )


# --------------------------------------------------------------------------
# the signature


def verify_ssh(document: Path, signature: Path, roster: dict, keyring: Path) -> str:
    """Verify an SSHSIG and return the principal it verified under.

    The principal is *discovered* with `find-principals` and then verified,
    rather than guessed by trying every roster entry in turn: trying each in
    turn would report success on the first that worked and say nothing about
    which key that was.
    """
    allowed = keyring / "allowed_signers"
    lines = []
    for who in roster["participants"]:
        key = who["key"]
        if key["type"] == "ssh":
            lines.append(f"{key['principal']} {key['public_key'].strip()}")
    if not lines:
        raise Refused(
            f"{signature.name} is an ssh signature and the roster contains no ssh keys"
        )
    allowed.write_text("\n".join(lines) + "\n")

    found = subprocess.run(
        ["ssh-keygen", "-Y", "find-principals", "-f", str(allowed), "-s", str(signature)],
        capture_output=True,
        text=True,
    )
    if found.returncode != 0 or not found.stdout.strip():
        raise Refused(
            f"{signature.name} was not made by any key on the roster. A signature from a "
            "key minted for the occasion is worth what no signature is worth while "
            f"looking like more. ({found.stderr.strip() or 'no principal found'})"
        )
    principals = sorted(set(found.stdout.split()))
    if len(principals) != 1:
        raise Refused(
            f"{signature.name} matches several roster principals ({', '.join(principals)}); "
            "two participants sharing a key are one participant"
        )
    principal = principals[0]

    verified = subprocess.run(
        [
            "ssh-keygen", "-Y", "verify",
            "-f", str(allowed),
            "-I", principal,
            "-n", "file",
            "-s", str(signature),
        ],
        stdin=document.open("rb"),
        capture_output=True,
        text=True,
    )
    if verified.returncode != 0:
        raise Refused(
            f"{signature.name} does not verify over {document.name}: "
            f"{verified.stderr.strip()}"
        )
    return principal


def verify_gpg(document: Path, signature: Path, roster: dict, keyring: Path) -> str:
    """Verify a clearsigned attestation against a keyring holding only the roster.

    A throwaway `GNUPGHOME` rather than the caller's: verifying against the
    operator's own keyring would make the answer depend on what that operator
    happens to have imported, and a verifier whose answer depends on who runs
    it is not a verifier.
    """
    home = keyring / "gnupg"
    home.mkdir(mode=0o700, exist_ok=True)
    # Resolve before restricting the child environment; installations outside
    # the system binary directories must still use the selected verifier.
    gpg = shutil.which("gpg")
    if gpg is None:
        raise Refused("gpg is not installed; it is required to verify a pgp signature")
    env = {"GNUPGHOME": str(home), "PATH": "/usr/bin:/bin", "LC_ALL": "C"}

    fingerprints = {}
    for who in roster["participants"]:
        key = who["key"]
        if key["type"] != "gpg":
            continue
        imported = subprocess.run(
            [gpg, "--batch", "--import"],
            input=key["public_key"],
            capture_output=True,
            text=True,
            env=env,
        )
        if imported.returncode != 0:
            raise Refused(f"{who['name']}'s pgp key did not import: {imported.stderr.strip()}")
        fingerprints[str(key.get("fingerprint", "")).upper()] = who["name"]
    if not fingerprints:
        raise Refused(
            f"{signature.name} is a pgp signature and the roster contains no pgp keys"
        )

    # Status on fd 2, payload on fd 1, so the machine-readable verdict and the
    # bytes that were signed come back from one run without being interleaved.
    checked = subprocess.run(
        [gpg, "--batch", "--status-fd", "2", "--output", "-", "--decrypt", str(signature)],
        capture_output=True,
        text=True,
        env=env,
    )
    valid = re.search(r"^\[GNUPG:\] VALIDSIG ([0-9A-F]+)", checked.stderr, re.M)
    if checked.returncode != 0 or not valid:
        raise Refused(
            f"{signature.name} does not verify against the roster's keys: "
            f"{checked.stderr.strip()}"
        )
    fingerprint = valid.group(1).upper()
    if fingerprint not in fingerprints:
        raise Refused(
            f"{signature.name} verifies under key {fingerprint}, which is not on the roster"
        )

    # The payload has to be *this* document, not merely something that key
    # signed. Without this a genuine signature over any other text, renamed,
    # would pass.
    if checked.stdout.strip() != document.read_text().strip():
        raise Refused(
            f"{signature.name} is a valid signature over something other than "
            f"{document.name}"
        )
    return fingerprints[fingerprint]


def has_identity_evidence(who: dict) -> bool:
    """Whether a register entry points anywhere a reader could check the key.

    `published_at` is a list of places outside this repository where the key
    can be seen to be that person's -- an account page, a keyserver, a
    personal domain. It is not fetched: whether a URL resolves today says
    little, and a verifier that depended on fetching would fail differently on
    every machine. What is checked is that the entry names somewhere at all.

    Deliberately not a refusal. An entry without evidence is a weak entry, not
    a broken ceremony, and refusing would fail a published ceremony over a
    field its own announcement introduced late. But it was silent before, and
    silence is the failure this repository keeps paying for: it took a
    contributor writing "no tool in this repository reports that absence" into
    their own attestation for the gap to be visible at all.
    """
    where = who.get("published_at")
    return isinstance(where, list) and any(str(item).strip() for item in where)


def find_signature(directory: Path, index: int) -> Path | None:
    for suffix in (".sig", ".asc"):
        candidate = directory / f"attestation-{index}.txt{suffix}"
        if candidate.exists():
            return candidate
    return None


# --------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    """The options this program accepts, separated so a test can ask.

    `ceremony-docs-tests.py` checks that the flags the participant guide tells
    people to type are flags this parser has. It used to ask by grepping
    `--help`, which is worthless here: `description=__doc__` prints the module
    docstring, and the docstring names the flags in prose, so the help output
    mentions `--in-progress` whether or not the parser does. Asking the parser
    through a subprocess failed differently -- argparse reports a missing
    required argument before an unrecognised one, so the probe never got to
    the question. Building the parser here lets the test look straight at it.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("ceremony", type=Path)
    parser.add_argument("--roster", type=Path, required=True)
    parser.add_argument("--attestations", type=Path)
    parser.add_argument(
        "--unattested-ok",
        default="",
        help="comma-separated contribution indices that may carry no signature",
    )
    parser.add_argument(
        "--in-progress",
        action="store_true",
        help="report the independence rule instead of enforcing it, for a "
             "participant checking their own work before the ceremony closes",
    )
    return parser


def main() -> int:
    options = build_parser().parse_args()

    attestations = options.attestations or options.ceremony.parent
    waived = {int(n) for n in options.unattested_ok.split(",") if n.strip()}

    record_path = options.ceremony / "ceremony.json"
    try:
        record = json.loads(record_path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise Refused(f"the record could not be read: {exc}") from exc
    if record.get("protocol") != PROTOCOL:
        raise Refused(f"the record is for protocol {record.get('protocol')!r}")

    roster = load_roster(options.roster)
    by_name = {who["name"]: who for who in roster["participants"]}
    principal_to_name = {}
    for who in roster["participants"]:
        if who["key"]["type"] == "ssh":
            principal_to_name[who["key"]["principal"]] = who["name"]

    contributions = [e for e in record.get("entries", []) if e.get("kind") == "participant"]
    if not contributions:
        raise Refused(
            "this record contains no participant contributions. A ceremony of nothing "
            "but a beacon step is a public random number, not a ceremony"
        )

    standing = []
    with tempfile.TemporaryDirectory(prefix="tos-phase2-roster-") as scratch:
        keyring = Path(scratch)
        for entry in contributions:
            index = entry["index"]
            document = attestations / f"attestation-{index}.txt"
            if not document.exists():
                raise Refused(
                    f"contribution {index} has no attestation. It appears in the record "
                    "and nothing ties it to anyone who can be asked"
                )

            fields = read_document(document, index)
            check_against_record(document, fields, entry, record)

            signature = find_signature(attestations, index)
            if signature is None:
                if index not in waived:
                    raise Refused(
                        f"contribution {index} is unsigned. Pass --unattested-ok {index} "
                        "to accept it deliberately; it then counts for nothing"
                    )
                print(f"  {index}  UNSIGNED, waived -- adds nobody to the trust set")
                standing.append((index, None))
                continue

            if signature.suffix == ".sig":
                principal = verify_ssh(document, signature, roster, keyring)
                name = principal_to_name[principal]
            else:
                name = verify_gpg(document, signature, roster, keyring)

            who = by_name[name]
            independence = (
                "independent of the operator"
                if who["independent_of_operator"]
                else "NOT independent of the operator"
            )
            evidence = "" if has_identity_evidence(who) else ", NO PUBLIC IDENTITY EVIDENCE"
            print(f"  {index}  signed by {name} -- {independence}{evidence}")
            standing.append((index, name))

    signed = [name for _, name in standing if name]
    independent = [n for n in signed if by_name[n]["independent_of_operator"]]
    unevidenced = sorted({n for n in signed if not has_identity_evidence(by_name[n])})

    print()
    print(f"{len(contributions)} contribution(s), {len(signed)} verified against the roster")

    if unevidenced:
        print()
        print(
            f"NO PUBLIC IDENTITY EVIDENCE for: {', '.join(unevidenced)}. The register "
            "carries no published_at for these keys, so a reader cannot trace the "
            "signature to anyone who can be asked afterwards, and being able to ask is "
            "the whole of what an attestation is worth. Their signatures still verify: "
            "what is missing is the person, not the cryptography."
        )

    if not independent:
        complaint = (
            "no verified contribution comes from a participant declared independent of "
            "the operator. The security argument is that one participant destroyed a "
            "scalar without the others being able to compel or observe them; with every "
            "contribution inside one party's control that reduces to 'trust us', which "
            "is what the ceremony existed to avoid"
        )
        if not options.in_progress:
            raise Refused(complaint)
        print()
        print(f"NOT YET SATISFIED: {complaint}.")
        print(
            "Reported rather than refused because --in-progress was passed. This is "
            "expected while the ceremony is still open, and it must be satisfied before "
            "the ceremony closes -- the final check is run without that flag."
        )
        return 0

    print(f"independent participants: {', '.join(sorted(independent))}")
    return 0


if __name__ == "__main__":
    if shutil.which("ssh-keygen") is None:
        print("ssh-keygen is not installed; it is the verifier, not a convenience", file=sys.stderr)
        sys.exit(2)
    try:
        sys.exit(main())
    except Refused as refusal:
        print(f"\nREFUSED: {refusal}", file=sys.stderr)
        sys.exit(1)
