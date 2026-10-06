"""Persistent SDK sessions using public fixture keys and controlled chain time only."""

import json
import os
import subprocess


class CachedFeeSession:
    def __init__(
        self,
        driver,
        out,
        *,
        tree,
        key,
        vault,
        epoch0,
        opened_time,
        successor=False,
        global_id=42,
        network=123,
        vm_version=17,
    ):
        out.mkdir(parents=True, exist_ok=True)
        journal = out / "journal"
        journal.mkdir(mode=0o700)
        self.out = out
        self.request = dict(
            global_id=global_id,
            network=f"{network:064x}",
            vm_version=vm_version,
            directory=str(journal.resolve()),
            tree=str(tree.resolve()),
            backend=(
                "/NO-EXTERNAL-FEE-SIGNER"
                if os.environ.get("TOS_TEST_REQUIRE_NATIVE_FEE") == "1"
                else os.environ["LMS_TOOL"]
            ),
            vault=f"{vault[1]:064x}",
            public_key=key.hex(),
            epoch0=epoch0,
            opened_time=opened_time,
            successor=successor,
            digest="00" * 32,
            leaf=0,
        )
        self.log = (out / "driver.log").open("w")
        self.process = subprocess.Popen(
            [str(driver.resolve()), "--serve-public-fixture"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=self.log,
            text=True,
        )
        self.count = 0

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.process.stdin.close()
        try:
            self.process.wait(timeout=30)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait()
            raise
        finally:
            self.process.stdout.close()
            self.log.close()
        assert self.process.returncode == 0

    def call(self, mode, now, **changes):
        request = {**self.request, "mode": mode, "proven_time": now, **changes}
        self.process.stdin.write(json.dumps(request) + "\n")
        self.process.stdin.flush()
        line = self.process.stdout.readline()
        assert line, "SDK fixture session exited unexpectedly"
        result = json.loads(line)
        self.count += 1
        (self.out / f"{self.count:02d}-{mode}.json").write_text(
            json.dumps({"request": request, "result": result}, indent=2) + "\n"
        )
        return result

    def wait_required(self, now):
        result = self.call("preview", now)
        assert "restore wait" in result.get("error", ""), result

    def signature(self, intent, now, leaf):
        plan = self.call("preview", now)
        assert plan == {"leaf": leaf, "backend_calls": 0}, plan
        args = dict(digest=intent.hash.hex(), leaf=leaf)
        signed = self.call("sign", now, **args)
        expected_route = {
            name: self.request[name] for name in ("global_id", "network", "vault", "epoch0")
        }
        expected_route["tree_id"] = f"{457 if self.request['successor'] else 456:064x}"
        assert signed["route"] == expected_route, "cached signer route mismatch"
        assert signed.get("verified") and signed["backend_calls"] == 1, signed
        if os.environ.get("TOS_TEST_REQUIRE_NATIVE_FEE") == "1":
            assert signed.get("backend_kind") == "native-lms", signed
        cached = self.call("retry", now, backend="/NO-PUBLIC-TEST-SIGNER", **args)
        assert cached["route"] == expected_route, "cached signer route mismatch"
        assert cached.get("verified") and cached["backend_calls"] == 0, cached
        assert cached["signature"] == signed["signature"]
        return bytes.fromhex(cached["signature"])
