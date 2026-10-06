"""Native signer guard controls: require semantic failure, then restore and retest."""

import argparse
import json
import resource
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "crypto/pq/wallet-pq-signer.cpp"


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--build", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    args.build = args.build.resolve()
    args.output.mkdir(parents=True, exist_ok=False)
    source = SOURCE.read_text()
    cases = [
        (
            "generate_rng",
            "RAND_priv_bytes(seed.bytes.data(), size) != 1",
            "RAND_priv_bytes(seed.bytes.data(), size) == -1",
            "test-wallet-pq-signer-rng",
            "generated wallet key after random source failure",
        ),
        (
            "sign_rng",
            "RAND_priv_bytes(random.bytes.data(), random_size) != 1",
            "RAND_priv_bytes(random.bytes.data(), random_size) == -1",
            "test-wallet-pq-signer-rng",
            "exported wallet signature after random source failure",
        ),
        (
            "verify",
            "verified != VerifyResult::valid",
            "verified == VerifyResult::valid && false",
            "test-wallet-pq-signer-rejection",
            "accepted rejected wallet signature",
        ),
        ("digest", "digest.size() != 32", "false", "test-wallet-pq-signer", "!key->sign"),
        ("domain", "ctx.empty()", "false", "test-wallet-pq-signer", "!key->sign"),
    ]
    targets = [
        "test-wallet-pq-signer",
        "test-wallet-pq-signer-rng",
        "test-wallet-pq-signer-rejection",
    ]

    def run(label, command):
        result = subprocess.run(command, capture_output=True, text=True, timeout=300)
        log = result.stdout + result.stderr
        (args.output / f"{label}.log").write_text(log)
        return result.returncode, log

    def build(label):
        code, log = run(
            label, ["cmake", "--build", str(args.build), "--target", *targets, "-j", "2"]
        )
        assert code == 0, log[-3000:]

    def positive(label):
        for target in targets:
            code, log = run(label + "-" + target, [str(args.build / "crypto/pq" / target)])
            assert code == 0, log[-3000:]

    results = {}
    try:
        build("baseline-build")
        positive("baseline")
        for label, old, new, target, failure in cases:
            assert source.count(old) == 1
            SOURCE.write_text(source.replace(old, new))
            build(label + "-build")
            code, log = run(label, [str(args.build / "crypto/pq" / target)])
            assert code != 0 and failure in log, log[-3000:]
            results[label] = {"exit": code, "semantic_failure": failure}
    finally:
        SOURCE.write_text(source)
        build("restored-build")
        positive("restored")
    (args.output / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    print("5 native wallet signer controls detected; restored three executables pass")


if __name__ == "__main__":
    main()
