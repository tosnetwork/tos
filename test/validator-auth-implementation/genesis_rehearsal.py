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


def compile_contract(build, work):
    """The configuration contract, built from source the way the chain builds it."""
    out = work / "contract"
    out.mkdir(parents=True, exist_ok=True)
    fif, boc = out / "config-code.fif", out / "config-code.boc"
    compiled = run([build / "crypto/func", "-PS", "-o", fif,
                    ROOT / "crypto/smartcont/stdlib.fc", ROOT / "crypto/smartcont/config-code.fc"])
    if compiled.returncode != 0:
        return None
    assembler = out / "assemble.fif"
    assembler.write_text('"Asm.fif" include\n"%s" include\n2 boc+>B "%s" B>file\n' % (fif, boc))
    assembled = run([build / "crypto/fift", "-I", ROOT / "crypto/fift/lib", "-s", assembler])
    if assembled.returncode != 0 or not boc.is_file():
        return None
    return boc


def seed_genesis_account(build, work, fift_path, election_boc):
    """Write the configuration account a genesis leaves behind, and one without.

    Both the configuration dictionary and the account cell are written by the
    genesis interpreter, through the same `config!` word a real genesis uses --
    which also validates each parameter against the schema, so a descriptor the
    chain could not hold would be refused here rather than executed.
    """
    source = work / "gen-account.fif"
    account = work / "genesis-account.boc"
    unseeded = work / "genesis-account-unseeded.boc"
    config = work / "genesis-config.boc"
    source.write_text("\n".join([
        '"TosUtil.fif" include',
        '"Config.fif" include',
        '"%s" file>B B>boc constant registry' % (work / "registry/config46.boc"),
        '"%s" file>B B>boc constant checkpoint' % (work / "registry/registry-checkpoint.boc"),
        '"%s" file>B B>boc constant vset' % election_boc,
        '// Version and capability are what make the chain design-active, and the',
        '// account below is what that activation then requires.',
        '16 1024 config.version!',
        '250 250 1000 23 true config.catchain_params!',
        '400 100 1 config.validator_num!',
        'vset 34 config!',
        'registry 46 config!',
        '( 0 1 9 10 16 28 34 46 ) config.mandatory_params!',
        '( 0 1 9 10 16 34 46 ) config.critical_params!',
        'configdict 2 boc+>B "%s" B>file' % config,
        '// cfg_dict, seqno, configuration master key, votes, and the checkpoint',
        '// beside the parameter. The key is zero: a genesis that appoints no',
        '// configuration dictator is the case this rehearsal is about.',
        '<b configdict ref, 0 32 u, 0 256 u, dictnew dict, checkpoint ref, b>',
        '2 boc+>B "%s" B>file' % account,
        '// The same account without it, which is the state the policy forbids.',
        '<b configdict ref, 0 32 u, 0 256 u, dictnew dict, b>',
        '2 boc+>B "%s" B>file' % unseeded,
        '."wrote genesis configuration account" cr',
    ]) + "\n")
    result = run([build / "crypto/create-state", "-s", source],
                 env={"FIFTPATH": fift_path, "PATH": "/usr/bin:/bin"})
    if result.returncode != 0 or not account.is_file() or not unseeded.is_file():
        return None, None, None
    return account, unseeded, config


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

    # The account a genesis leaves behind, and whether the chain it starts can
    # make its first block.
    #
    # The contract refuses a design-active chain whose configuration account
    # carries no registry checkpoint: on such a chain that is not an account
    # yet to migrate, it is one whose configuration context can never open. That
    # refusal presumes a genesis seeds the parameter and the checkpoint
    # together, and a rule about what genesis writes cannot be established by a
    # fixture that writes it in the same place that reads it. So the account is
    # written here by the genesis interpreter, from the registry and the
    # descriptors the real writers produced, and then executed.
    contract = compile_contract(args.build, work)
    if not record("configuration-contract-built", contract is not None):
        failures += 1
    else:
        seeded, unseeded, config = seed_genesis_account(args.build, work, fift_path, authenticated)
        if not record("genesis-account-written", seeded is not None):
            failures += 1
        else:
            checkpoint = work / "registry/registry-checkpoint.boc"
            started = run([binaries / "p0-genesis-account-probe", "--contract", contract,
                           "--account", seeded, "--config", config, "--checkpoint", checkpoint,
                           "--expect-exit", "0"])
            if not record("a-seeded-genesis-account-makes-its-first-block", started.returncode == 0,
                          started.stdout + started.stderr):
                failures += 1
            # And the state the policy says cannot exist is refused rather than
            # migrated, so the case above is about the seeding and not about the
            # account being loadable at all.
            refused = run([binaries / "p0-genesis-account-probe", "--contract", contract,
                           "--account", unseeded, "--config", config, "--checkpoint", checkpoint,
                           "--expect-exit", "47"])
            if not record("an-unseeded-genesis-account-is-refused", refused.returncode == 0,
                          refused.stdout + refused.stderr):
                failures += 1

    report["failures"] = failures
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n")
    print("SUMMARY: %d cases, %d failed" % (len(report["cases"]), failures))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
