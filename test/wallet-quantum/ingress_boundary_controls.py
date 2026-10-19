"""Prove native structural ingress boundary tests detect deleted production guards."""

import argparse
import json
import subprocess
from pathlib import Path

from native_control_log import retain_output

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "validator/impl/external-message-parser.cpp"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    original = SOURCE.read_text()
    cases = [
        ("size", "data.size() > limits.max_size", "false", "SerializedSizeBoundary"),
        (
            "depth",
            "ext_msg->get_depth() >= limits.max_depth",
            "ext_msg->get_depth() > limits.max_depth",
            "DepthBoundary",
        ),
    ]
    for _, old, _, _ in cases:
        assert original.count(old) == 1

    def run(label, test="ExtMessageIngress"):
        built = subprocess.run(
            [
                "cmake",
                "--build",
                str(args.build),
                "--target",
                "test-ext-message-ingress",
                "-j",
                "2",
            ],
            capture_output=True,
            timeout=600,
        )
        build_log = retain_output(args.output, label + "-build", built)
        assert built.returncode == 0, build_log[-4000:]
        result = subprocess.run(
            [str((args.build / "test-ext-message-ingress").resolve()), "--filter", test],
            capture_output=True,
            timeout=60,
        )
        log = retain_output(args.output, label, result)
        return result.returncode, log

    results = {}
    try:
        code, log = run("baseline")
        assert code == 0 and "2 test(s) passed" in log, log
        for name, old, new, test in cases:
            SOURCE.write_text(original.replace(old, new))
            code, log = run(name, "ExtMessageIngress_" + test)
            assert code != 0 and test in log and "rejected.is_error()" in log, log
            results[name] = {
                "exit": code,
                "witness": "forbidden message parsed successfully",
                "test": test,
            }
            SOURCE.write_text(original)
    finally:
        SOURCE.write_text(original)
        code, log = run("restored")
        assert code == 0 and "2 test(s) passed" in log, log
    (args.output / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    print("Two native ingress boundary controls detected; restored tests pass")


if __name__ == "__main__":
    main()
