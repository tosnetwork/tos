"""Bind real fixture POP signatures to Rust SDK request and PPS3 bytes."""

import json
import subprocess

from cells import Cell, from_boc


class PopEncoder:
    def __init__(self, driver, signer):
        self.driver = driver.resolve()
        self.signer = signer
        self.calls = []

    def signed(self, sign, challenge, role, **kwargs):
        s = challenge.slice()
        assert s.uint(32) == 0x504F5033
        global_id, network, encoded_role = s.sint(32), s.uint(256), s.uint(8)
        nonce, deadline = s.uint(256), s.uint(32)
        parties, keys = s.ref().slice(), s.ref().slice()
        s.end()
        account, module = parties.addr(), parties.uint(256)
        parties.end()
        assert keys.uint(8) == 1 and account[0] == 0 and role == encoded_role
        primary, rescue, policy = keys.uint(256), keys.uint(256), keys.uint(8)
        keys.end()
        payload = dict(
            global_id=global_id,
            network=f"{network:064x}",
            role=role,
            challenge=f"{nonce:064x}",
            deadline=deadline,
            proven_time=deadline - 600,
            account=f"{account[1]:064x}",
            module=f"{module:064x}",
            primary_key_hash=f"{primary:064x}",
            rescue_key=f"{rescue:064x}",
            policy=policy,
        )

        def encode(request):
            result = subprocess.run(
                [str(self.driver)], input=json.dumps(request), capture_output=True, text=True
            )
            assert result.returncode == 0, result.stderr
            return json.loads(result.stdout)

        encoded = encode(payload)
        actual = from_boc(bytes.fromhex(encoded["request"]))
        assert actual.hash == challenge.hash
        assert encoded["digest"] == Cell().raw(b"TOS-POP1").ref(challenge).hash.hex()
        assert encoded["context"] == b"TOS-RESCUE-POP-v1".hex()
        sig = self.signer(sign, actual, role, **kwargs)
        pieces, current = [], sig
        while current is not None:
            assert len(current.bits) % 8 == 0 and len(current.refs) <= 1
            pieces.append(int(current.bits, 2).to_bytes(len(current.bits) // 8, "big"))
            current = current.refs[0] if current.refs else None
        submission = encode({**payload, "signature": b"".join(pieces).hex()})
        body = from_boc(bytes.fromhex(submission["submission"]))
        assert body.hash == Cell().uint(0x50505333, 32).ref(challenge).ref(sig).hash
        self.calls.append({"input": payload, "output": submission})
        return body.refs[1]
