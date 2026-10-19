"""Require wallet observation and request tests to fail after binding guard deletions."""

import argparse
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "tosctl/src/node-control/contracts/src/wallet_quantum_wallet_state.rs"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    source = SOURCE.read_text()
    guards = [
        ("live", "wallet authorization needs a live proof", "accepted bad wallet observation live"),
        (
            "checkpoint",
            "wallet/module proof checkpoints differ",
            "accepted bad wallet observation checkpoint",
        ),
        (
            "wallet_address",
            "wallet address differs from enrollment",
            "accepted bad wallet observation wallet_address",
        ),
        (
            "module_address",
            "module address differs from enrollment",
            "accepted bad wallet observation module_address",
        ),
        ("code", "wallet/module code mismatch", "accepted bad wallet observation code"),
        (
            "module_data",
            "deployed module data mismatch",
            "accepted bad wallet observation module_data",
        ),
        (
            "installed",
            "wallet installed module/fee tuple mismatch",
            "accepted uninstalled successor",
        ),
        ("freshness", "stale wallet/module proof", "accepted bad wallet observation stale_module"),
    ]
    cases = []
    for label, message, reason in guards:
        marker = json.dumps(message)
        assert source.count(marker) == 1
        at = source.index(marker)
        start = source.rfind("anyhow::ensure!(", 0, at)
        end = source.index(");", at) + 2
        assert start >= 0
        cases.append((label, source[:start] + source[end:], reason))
    classic = 'anyhow::ensure!(!s.get_next_bit()?, "classic authorization flag enabled");'
    assert source.count(classic) == 1
    cases.append(
        (
            "classic",
            source.replace(classic, "s.get_next_bit()?;"),
            "accepted bad wallet observation classic",
        )
    )
    # Each counter guard is deleted on its own, so one surviving guard cannot
    # hide the loss of another.
    rescue_seqno = (
        'anyhow::ensure!(self.rescue_nonce < u64::MAX, "rescue nonce exhausted");\n'
        '                anyhow::ensure!(self.seqno < u32::MAX, "wallet seqno exhausted");'
    )
    configure_seqno = (
        'anyhow::ensure!(self.seqno < u32::MAX, "wallet seqno exhausted");\n'
        '                anyhow::ensure!(self.epoch < u64::MAX, "wallet epoch exhausted");'
    )
    primary = "self.primary_nonce < u64::MAX && self.seqno < u32::MAX"
    assert source.count("self.seqno < u32::MAX") == 3
    for label, old, new, reason in [
        (
            "nonce",
            rescue_seqno,
            rescue_seqno.replace("self.rescue_nonce < u64::MAX", "true"),
            "accepted exhausted execute counter",
        ),
        (
            "seqno",
            rescue_seqno,
            rescue_seqno.replace("self.seqno < u32::MAX", "true"),
            "accepted exhausted execute counter",
        ),
        (
            "configure_seqno",
            configure_seqno,
            configure_seqno.replace("self.seqno < u32::MAX", "true"),
            "accepted exhausted configure counter",
        ),
        (
            "primary_nonce",
            primary,
            primary.replace("self.primary_nonce < u64::MAX", "true"),
            "accepted exhausted primary counter",
        ),
        (
            "primary_seqno",
            primary,
            primary.replace("self.seqno < u32::MAX", "true"),
            "accepted exhausted primary counter",
        ),
    ]:
        assert source.count(old) == 1, label
        cases.append((label, source.replace(old, new), reason))

    def run(label):
        result = subprocess.run(
            [
                "cargo",
                "test",
                "--manifest-path",
                str(ROOT / "tosctl/src/Cargo.toml"),
                "--locked",
                "-p",
                "contracts",
                "--lib",
                "--",
                "proven_wallet",
                "primary_request_requires_current_proven_policy",
            ],
            capture_output=True,
            text=True,
        )
        log = result.stdout + result.stderr
        (args.output / f"{label}.log").write_text(log)
        return result.returncode, log

    results = {}
    try:
        code, log = run("baseline")
        assert code == 0 and "6 passed" in log, log[-3000:]
        for label, mutated, reason in cases:
            SOURCE.write_text(mutated)
            code, log = run(label)
            assert code != 0 and " ... FAILED" in log and reason in log, log[-3000:]
            results[label] = {"exit": code, "semantic_failure": reason}
    finally:
        SOURCE.write_text(source)
        code, log = run("restored")
        assert code == 0 and "6 passed" in log, log[-3000:]
    (args.output / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    print(f"{len(results)} wallet state guard controls detected; restored tests pass")


if __name__ == "__main__":
    main()
