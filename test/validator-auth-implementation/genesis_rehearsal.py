"""Drive a P0 genesis through the real writers and the node's committee reader.

The registry comes from the production encoder and the validator descriptors
from the genesis interpreter. Neither is rebuilt in the reader's language, so a
pass here is agreement between three separate implementations rather than one
implementation agreeing with itself.

Every positive case is paired with the change that must break it.
"""
import argparse
import json
import hashlib
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def run(command, **kwargs):
    return subprocess.run([str(c) for c in command], capture_output=True, text=True, **kwargs)


def fift_source(bindings, out_boc, word, mutate=None):
    lines = ['"TosUtil.fif" include', '"Asm.fif" include', '"Lists.fif" include']
    for entry in bindings:
        identity, stake = entry["identity"], entry["stake_id"]
        if mutate == "zero-identity":
            identity = "0" * 64
        if mutate == "zero-stake":
            stake = "0" * 64
        prefix = 'B{%s} B{%s} 256 B>u@' % (entry["public_key"], entry["adnl"])
        if word == "auth":
            lines.append('%s 0x%s 0x%s %d add-auth-validator' % (prefix, identity, stake, entry["weight"]))
        else:
            lines.append('%s %d add-adnl-validator' % (prefix, entry["weight"]))
    # config.validators! inlined so the descriptors reach a file the reader opens
    # instead of a configuration dictionary this script would have to re-encode.
    lines += [
        '0 10000 0',
        '?dup 0= { validator# } if',
        'validator# 0= abort"no initial validators defined"',
        'rot <b x{12} s, swap 32 u, rot 32 u, validator# 16 u, swap 16 u,',
        'validators-weight @ 64 u, validator-dict @ first dict, b>',
        '2 boc+>B "%s" B>file' % out_boc,
        '." wrote " validator# . ." descriptors" cr',
    ]
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--members", type=int, default=4)
    args = parser.parse_args()

    binaries = args.build / "test/validator-auth-implementation"
    create_state = args.build / "crypto/create-state"
    fift_path = ":".join(
        str(p) for p in (ROOT / "crypto/fift/lib", ROOT / "crypto/smartcont", args.build / "crypto/smartcont")
    )
    work = args.work
    work.mkdir(parents=True, exist_ok=True)
    domain = hashlib.sha256(b"tos-p0-genesis-rehearsal").hexdigest()

    members = work / "members.txt"
    with members.open("w") as handle:
        for index in range(args.members):
            key = hashlib.sha256(("rehearsal-network-key-%d" % index).encode()).hexdigest()
            adnl = hashlib.sha256(("rehearsal-adnl-%d" % index).encode()).hexdigest()
            handle.write("%s %s %d\n" % (key, adnl, index + 1))

    report = {"domain": domain, "members": args.members, "cases": []}

    def record(name, ok, detail=""):
        report["cases"].append({"case": name, "ok": bool(ok), "detail": detail[:400]})
        print(("PASS  " if ok else "FAIL  ") + name + ("  " + detail[:160] if detail and not ok else ""))
        return ok

    failures = 0
    genesis = run([binaries / "p0-genesis-tool", "--members", members, "--out", work / "registry",
                   "--chain-domain", domain, "--valid-until", 4000000000])
    if not record("genesis-registry", genesis.returncode == 0, genesis.stdout + genesis.stderr):
        failures += 1
        json.dump(report, args.out.open("w"), indent=2)
        return 1
    bindings = json.loads((work / "registry/bindings.json").read_text())

    def build(word, name, mutate=None):
        source = work / ("gen-%s.fif" % name)
        boc = work / ("vset-%s.boc" % name)
        source.write_text(fift_source(bindings, boc, word, mutate))
        result = run([create_state, "-s", source], env={"FIFTPATH": fift_path, "PATH": "/usr/bin:/bin"})
        return result, boc

    result, authenticated = build("auth", "auth")
    if not record("genesis-descriptors", result.returncode == 0, result.stdout + result.stderr):
        failures += 1

    probe = run([binaries / "p0-vset-probe", authenticated])
    if not record("production-unpacker-reads-bindings", probe.returncode == 0, probe.stdout + probe.stderr):
        failures += 1

    derive = run([binaries / "p0-genesis-probe", "--registry", work / "registry/config46.boc",
                  "--election", authenticated, "--chain-domain", domain])
    if not record("native-committee-derived", derive.returncode == 0, derive.stdout + derive.stderr):
        failures += 1

    # Negative controls. A genesis path that cannot produce a refusal is not
    # evidence that it produced an authenticated committee.
    legacy_result, legacy = build("adnl", "legacy")
    if not record("legacy-descriptors-written", legacy_result.returncode == 0,
                  legacy_result.stdout + legacy_result.stderr):
        failures += 1
    legacy_probe = run([binaries / "p0-vset-probe", legacy])
    if not record("legacy-descriptors-have-no-binding",
                  legacy_probe.returncode != 0 and "unbound-members" in legacy_probe.stderr,
                  legacy_probe.stdout + legacy_probe.stderr):
        failures += 1
    legacy_derive = run([binaries / "p0-genesis-probe", "--registry", work / "registry/config46.boc",
                         "--election", legacy, "--chain-domain", domain,
                         "--expect", "election-binding-required"])
    if not record("legacy-committee-refused", legacy_derive.returncode == 0,
                  legacy_derive.stdout + legacy_derive.stderr):
        failures += 1

    for mutate, label in (("zero-identity", "zero-identity-refused"), ("zero-stake", "zero-stake-refused")):
        bad, _ = build("auth", mutate, mutate)
        if not record(label, bad.returncode != 0, bad.stdout + bad.stderr):
            failures += 1

    disabled = run([binaries / "p0-genesis-probe", "--registry", work / "registry/config46.boc",
                    "--election", authenticated, "--chain-domain", domain,
                    "--capability", "0", "--expect", "committee-capability"])
    if not record("capability-gate-refuses", disabled.returncode == 0, disabled.stdout + disabled.stderr):
        failures += 1

    # A registry from a different chain must not authorize this committee even
    # though every descriptor in it is well formed.
    other = hashlib.sha256(b"tos-p0-genesis-rehearsal-other").hexdigest()
    foreign = run([binaries / "p0-genesis-tool", "--members", members, "--out", work / "foreign",
                   "--chain-domain", other, "--valid-until", 4000000000])
    if not record("foreign-registry-built", foreign.returncode == 0, foreign.stdout + foreign.stderr):
        failures += 1
    mismatch = run([binaries / "p0-genesis-probe", "--registry", work / "foreign/config46.boc",
                    "--election", authenticated, "--chain-domain", domain])
    if not record("foreign-registry-refused",
                  mismatch.returncode != 0 and "chain-domain-mismatch" in mismatch.stderr,
                  mismatch.stdout + mismatch.stderr):
        failures += 1

    report["failures"] = failures
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n")
    print("SUMMARY: %d cases, %d failed" % (len(report["cases"]), failures))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
