"""Use SDK intent/external bytes around actual journal-backed LMS signatures."""

import json
import subprocess

from cells import Cell, from_boc
from test_identity import chain


class FeeEncoder:
    def __init__(self, driver, out, epoch0):
        self.driver, self.out, self.epoch0 = driver.resolve(), out, epoch0
        out.mkdir(parents=True, exist_ok=True)
        self.count = 0

    def encode(self, intent, now, signature=None):
        s = intent.slice()
        assert s.uint(32) == 0x46454534
        assert s.uint(136) == int.from_bytes(b"TOS-RESCUE-FEE-v1", "big")
        kind, vault, config_hash, leaf, deadline, value = (
            s.uint(8),
            s.addr(),
            s.uint(256),
            s.uint(32),
            s.uint(32),
            s.coins(),
        )
        payload = s.ref()
        s.end()
        assert vault[0] == 0
        request = dict(
            class_=kind,
            vault=f"{vault[1]:064x}",
            config_hash=f"{config_hash:064x}",
            leaf=leaf,
            deadline=deadline,
            value=str(value),
            epoch0=self.epoch0,
            proven_time=now,
            payload=payload.boc().hex(),
            signature=None if signature is None else signature.hex(),
        )
        request["class"] = request.pop("class_")
        result = subprocess.run(
            [str(self.driver)], input=json.dumps(request), capture_output=True, text=True
        )
        assert result.returncode == 0, result.stderr
        response = json.loads(result.stdout)
        actual = from_boc(bytes.fromhex(response["intent"]))
        assert actual.hash == intent.hash and response["digest"] == intent.hash.hex()
        assert response["leaf"] == leaf
        self.count += 1
        (self.out / f"{self.count:02d}.json").write_text(
            json.dumps({"input": request, "output": response}, indent=2) + "\n"
        )
        if signature is not None:
            body = from_boc(bytes.fromhex(response["external"]))
            assert body.hash == Cell().ref(intent).ref(chain(signature)).hash
            return body
        return actual
