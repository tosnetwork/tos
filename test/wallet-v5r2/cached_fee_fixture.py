"""Real public-test LMS signer -> SDK journal/cache -> independently verified retry."""

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path


def signature(driver, out, *, tree, key, vault, digest, now, epoch0):
    out.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="sdk-cache-", dir=out) as tmp:
        journal = Path(tmp).resolve()
        request = {
            "directory": str(journal),
            "tree": str(tree.resolve()),
            "backend": os.environ["LMS_TOOL"],
            "vault": f"{vault:064x}",
            "digest": digest.hex(),
            "public_key": key.hex(),
            "epoch0": epoch0,
            "opened_time": now - 3600,
            "proven_time": now,
            "leaf": 8,
        }

        def run(name, changes, expected_failure=None):
            payload = {**request, **changes}
            src, dst = out / f"{name}-input.json", out / f"{name}-output.json"
            src.write_text(json.dumps(payload, indent=2) + "\n")
            result = subprocess.run(
                [str(driver.resolve()), str(src), str(dst)], capture_output=True, text=True
            )
            (out / f"{name}.log").write_text(result.stdout + result.stderr)
            if expected_failure is not None:
                assert result.returncode != 0 and expected_failure in result.stderr
                return None
            assert result.returncode == 0, result.stderr
            return json.loads(dst.read_text())

        signed = run("sign", {"mode": "sign"})
        assert signed["backend_calls"] == 1 and signed["verified"]
        # A different process reopens the journal at current time. An unavailable
        # backend proves that the retry cannot quietly generate another signature.
        retry = {"mode": "retry", "opened_time": now, "backend": str(journal / "NO-SIGNER")}
        cached = run("retry", retry)
        assert cached["backend_calls"] == 0 and cached["verified"]
        assert cached["signature"] == signed["signature"]
        run(
            "wrong-intent",
            {**retry, "digest": bytes([digest[0] ^ 1]).hex() + digest[1:].hex()},
            "cache intent mismatch",
        )
        bad_key = key[:-1] + bytes([key[-1] ^ 1])
        run(
            "wrong-key",
            {**retry, "public_key": bad_key.hex()},
            "cached signature failed real verification",
        )
        # Reopening may read old cached bytes, but must not sign in the old slot.
        run(
            "restart-sign",
            {"mode": "sign", "opened_time": now, "leaf": 9, "backend": str(journal / "NO-SIGNER")},
            "restore wait",
        )
        shutil.copytree(journal, out / "retained-journal", dirs_exist_ok=True)

        corrupted = journal / "corrupted-backend"
        corrupted.mkdir(mode=0o700)
        refused = run("corrupt-output", {"mode": "corrupt", "directory": str(corrupted)})
        assert refused == {"rejected": True, "backend_calls": 1, "next_leaf": 9}
        shutil.copytree(corrupted, out / "retained-corrupt-journal", dirs_exist_ok=True)
        (out / "summary.json").write_text(
            json.dumps(
                {
                    "real_lms_signature": True,
                    "independent_rust_vm_verification": True,
                    "signer_calls": 1,
                    "restart_retry_signer_calls": 0,
                    "retry_bytes_identical": True,
                    "wrong_intent_rejected": True,
                    "wrong_public_key_rejected": True,
                    "restart_signing_blocked": True,
                    "corrupted_backend_rejected_and_leaf_burned": True,
                    "scope": "Public deterministic test key, fixture chain time; not production custody",
                },
                indent=2,
            )
            + "\n"
        )
        return bytes.fromhex(cached["signature"])
