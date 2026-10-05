"""Persistent SDK sessions using public fixture keys and controlled chain time only."""

import json
import os
import subprocess


class CachedFeeSession:
    def __init__(self, driver, out, *, tree, key, vault, epoch0, opened_time, successor=False):
        out.mkdir(parents=True, exist_ok=True)
        journal = out / "journal"
        journal.mkdir(mode=0o700)
        self.out = out
        self.request = dict(
            directory=str(journal.resolve()),
            tree=str(tree.resolve()),
            backend=os.environ["LMS_TOOL"],
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
        assert signed.get("verified") and signed["backend_calls"] == 1, signed
        cached = self.call("retry", now, backend="/NO-PUBLIC-TEST-SIGNER", **args)
        assert cached.get("verified") and cached["backend_calls"] == 0, cached
        assert cached["signature"] == signed["signature"]
        return bytes.fromhex(cached["signature"])
