#!/usr/bin/env python3
"""Remove one production guard at a time and require its specific regression to fail.

Run only in an owned checkout with no concurrent builds. Restore source bytes in
finally blocks and rebuild the restored targets; retain small failure receipts.
"""

import argparse
import hashlib
import json
import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CASES = (
    # Without the GET scalar conversion a canonical seqno stays a string, the
    # strict parser refuses it with -32602 at HTTP 200, and the fixture's
    # saturated-budget answer (RATE_LIMITED) is never reached.
    (
        "get-url-scalars",
        "validator-engine/json-rpc-server.cpp",
        'if (key == "workchain" || key == "seqno" || key == "unixtime" || key == "param" || key == "config_id") {',
        'if (false && (key == "workchain" || key == "seqno" || key == "unixtime" || key == "param" || key == "config_id")) {',
        "test-json-rpc-transport",
        "+explorer_get_normalizes",
        "Expectation failed: body.find(path.second ?",
    ),
    # The HTTP saturation fixture deliberately owns no backend. Removing the
    # admission guard must hit this exact backend-access trap, never an unrelated
    # assertion, while the restored route must return 429 without reaching it.
    (
        "response-budget",
        "validator-engine/json-rpc-server-explorer.cpp",
        "if (!response_reservation)",
        "if (false && !response_reservation)",
        "test-json-rpc-transport",
        "+explorer_output_saturation",
        "[!explorer-query]\tCheck `!empty()` failed",
    ),
    (
        "cell-depth",
        "validator-engine/json-rpc-explorer.cpp",
        "if (seen.size() > 2048 || cell->get_depth() > 128)",
        "if (seen.size() > 2048)",
        "test-json-rpc-explorer",
        "+inspection_has_depth",
        "result.is_error()",
    ),
    (
        "policy-deadline",
        "validator-engine/json-rpc-explorer.cpp",
        "(policy.deadline && now >= policy.deadline)",
        "(policy.deadline && now > policy.deadline)",
        "test-json-rpc-explorer",
        "+policy_deadline_uses",
        "at_deadline_retired",
    ),
    (
        "backward-state-proof",
        "crypto/block/check-proof.cpp",
        "auto err = link.validate(",
        "auto err = !link.is_fwd ? td::Status::OK() : link.validate(",
        "test-json-rpc-explorer",
        "+ordinary_predecessor",
        "refused.is_error()",
    ),
    (
        "full-block-identity",
        "validator-engine/json-rpc-explorer.cpp",
        "if (block_id && *block_id != resolved)",
        "if (false && block_id && *block_id != resolved)",
        "test-json-rpc-explorer",
        "+selectors_are",
        "failure.is_error()",
    ),
    (
        "worker-permit-lifetime",
        "validator-engine/json-rpc-explorer.cpp",
        "[permit, work = std::move(work)]",
        "[work = std::move(work)]",
        "test-json-rpc-explorer",
        "+cancelled_running",
        "premature == nullptr",
    ),
    (
        "code-identity",
        "validator-engine/json-rpc-explorer-account.cpp",
        "if (entry.code->get_hash() == code->get_hash())",
        'if (entry.code->get_hash() == code->get_hash() || entry.family == "quantum_module_v1")',
        "test-json-rpc-explorer",
        "+exact_registry",
        "unknown.ok().family.empty()",
    ),
    (
        "trusted-historical-session",
        "crypto/block/signature-set.cpp",
        "if (carried_session_id != context.expected_session_id)",
        "if (false && carried_session_id != context.expected_session_id)",
        "test-pq-lite-forward-proof",
        None,
        "explorer accepted self-declared session",
    ),
)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir", type=Path, default=ROOT / "build")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--case", choices=[case[0] for case in CASES])
    args = parser.parse_args()
    build, out = args.build_dir.resolve(), args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    receipts = []
    env = os.environ.copy()
    if (
        sysroot := subprocess.run(
            ["xcrun", "--show-sdk-path"], capture_output=True, text=True
        ).stdout.strip()
        if os.uname().sysname == "Darwin"
        else None
    ):
        env["SDKROOT"] = sysroot

    def rebuild(target, path):
        with path.open("w") as log:
            subprocess.run(
                ["cmake", "--build", str(build), "--target", target, "-j", "6"],
                cwd=ROOT,
                env=env,
                stdout=log,
                stderr=log,
                check=True,
                timeout=600,
            )

    for name, relative, guard, replacement, target, selected, expected in CASES:
        if args.case and args.case != name:
            continue
        source = ROOT / relative
        original = source.read_text()
        assert original.count(guard) == 1, (name, "guard count")
        command = [str(build / target)]
        if selected:
            command += ["--filter", selected, "--verbosity", "0"]
        modified = original.replace(guard, replacement)
        if name == "worker-permit-lifetime":
            assert (
                modified.count("[permit = std::move(permit), completion = std::move(completion)]")
                == 1
            )
            modified = modified.replace(
                "[permit = std::move(permit), completion = std::move(completion)]",
                "[completion = std::move(completion)]",
            )
        try:
            source.write_text(modified)
            rebuild(target, out / (name + "-red-build.log"))
            red = subprocess.run(
                command, cwd=build, env=env, text=True, capture_output=True, timeout=60
            )
            raw = red.stdout + red.stderr
            (out / (name + "-red.log")).write_text(raw)
            assert red.returncode != 0 and expected in raw, (name, red.returncode, raw[-3000:])
        finally:
            source.write_text(original)
            assert source.read_text() == original
            rebuild(target, out / (name + "-restore-build.log"))
        green = subprocess.run(
            command, cwd=build, env=env, text=True, capture_output=True, timeout=60
        )
        raw_green = green.stdout + green.stderr
        (out / (name + "-green.log")).write_text(raw_green)
        assert green.returncode == 0, (name, raw_green[-3000:])
        receipts.append(
            {
                "case": name,
                "source": relative,
                "source_sha256": hashlib.sha256(original.encode()).hexdigest(),
                "command": command,
                "expected_failure": expected,
                "red_exit": red.returncode,
                "green_exit": green.returncode,
                "failure_lines": [line for line in raw.splitlines() if expected in line][:3],
            }
        )
        (out / "controls.json").write_text(json.dumps(receipts, indent=2) + "\n")
        print(name + ": intended rejection fails without guard; passes restored", flush=True)


if __name__ == "__main__":
    main()
