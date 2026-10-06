"""Require real checker tests to detect disabling stop-on-accept.

Run exclusively; the execution-config source is restored and rebuilt in finally.
"""

import argparse
import hashlib
import json
import subprocess
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--container")
    parser.add_argument("--container-source-dir", default="/checkout")
    parser.add_argument("--build-dir", required=True)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)
    relative = "validator/impl/external-message.cpp"
    source = root / relative
    original = source.read_bytes()
    anchor = b"exec_config->compute_phase_cfg.stop_on_accept_message = true;"
    assert original.count(anchor) == 1
    results = {}
    if args.container:
        for name in [
            relative,
            "test/test-ext-message-pool.cpp",
            "test/wallet-v5r2/post-accept-probe.boc",
        ]:
            actual = subprocess.check_output(
                [
                    "docker",
                    "exec",
                    args.container,
                    "sha256sum",
                    args.container_source_dir + "/" + name,
                ],
                text=True,
            ).split()[0]
            assert actual == hashlib.sha256((root / name).read_bytes()).hexdigest(), (
                "container source mismatch"
            )

    def run(command, label):
        if args.container:
            command = ["docker", "exec", args.container, *command]
        with (output / (label + ".log")).open("w") as log:
            result = subprocess.run(command, cwd=root, stdout=log, stderr=subprocess.STDOUT)
        results[label] = result.returncode
        return result.returncode

    def build(label):
        if args.container:
            target = args.container_source_dir + "/" + relative
            subprocess.run(["docker", "cp", str(source), args.container + ":" + target], check=True)
            subprocess.run(["docker", "exec", args.container, "touch", target], check=True)
        assert (
            run(
                ["cmake", "--build", args.build_dir, "--target", "test-ext-message-pool", "-j2"],
                label + "-build",
            )
            == 0
        )

    binary = args.build_dir + "/test-ext-message-pool"
    assert run([binary], "baseline") == 0
    try:
        source.write_bytes(original.replace(anchor, anchor.replace(b"true", b"false")))
        build("disabled-stop")
        code = run(
            [binary, "--filter", "WorkBudgetChargesAcceptedOrdinaryVmStopsAtAccept"],
            "disabled-stop",
        )
        failure = (output / "disabled-stop.log").read_text()
        assert code != 0 and "WorkBudgetChargesAcceptedOrdinaryVmStopsAtAccept" in failure
        assert "Expectation failed" in failure and "gas: used=116106" in failure
    finally:
        source.write_bytes(original)
        build("restored")
    assert run([binary], "restored") == 0
    report = dict(
        passed=True,
        runs=results,
        restored_green=True,
        source_sha256=hashlib.sha256(original).hexdigest(),
        scope="Real pool/checker with synthetic masterchain state and owner-controlled account; no network or CPU calibration",
    )
    (output / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report))


if __name__ == "__main__":
    main()
