"""Adapt public deterministic fixture keys to the real native wallet PQ signer."""

import json
import subprocess
from pathlib import Path
from unittest.mock import patch

from cells import Cell
from test_identity import chain
from test_rescue_e2e import Signers


class NativeSignerFixture:
    def __init__(self, driver):
        self.driver = driver.resolve()
        self.calls = []
        self.rescue_keys = {}

    def install(self, stack):
        import test_pop
        import test_preparation

        original = Signers.__init__

        def initialize(sign, directory):
            original(sign, directory)
            self.rescue_keys[sign.slh_sk] = "rescue"
            self.rescue_keys[sign.other_slh_sk] = "next-rescue"

        stack.enter_context(patch.object(Signers, "__init__", initialize))
        stack.enter_context(
            patch.object(Signers, "ml", lambda sign, d: self.primary(sign, d, "auth"))
        )
        stack.enter_context(
            patch.object(Signers, "slh", lambda sign, d, sk=None: self.rescue(sign, d, "auth", sk))
        )
        stack.enter_context(patch.object(test_pop, "signed", self.pop))
        stack.enter_context(patch.object(test_preparation, "signed", self.preparation))

    def invoke(self, key, purpose, digest, expected_public):
        result = subprocess.run(
            [str(self.driver), "--public-fixture", key, purpose, digest.hex()],
            capture_output=True,
            text=True,
            check=True,
            timeout=60,
        )
        output = json.loads(result.stdout)
        assert bytes.fromhex(output["public_key"]) == expected_public
        signature = bytes.fromhex(output["signature"])
        assert len(signature) == (2420 if "primary" in key else 7856)
        self.calls.append({"key": key, "purpose": purpose, "digest": digest.hex(), **output})
        return signature

    def primary(self, sign, digest, purpose):
        path = Path(sign.ml_sk)
        key = {"ml.sk": "primary", "successor-ml.sk": "next-primary"}[path.name]
        return self.invoke(key, purpose, digest, path.with_suffix(".pk").read_bytes())

    def rescue(self, sign, digest, purpose, sk=None):
        secret = sk or sign.slh_sk
        key = self.rescue_keys[secret]
        # Existing public fixture tools independently derive these public bytes.
        public = bytes.fromhex(secret)[32:]
        return self.invoke(key, purpose, digest, public)

    def pop(self, sign, challenge, role, context=b"TOS-RESCUE-POP-v1"):
        assert context == b"TOS-RESCUE-POP-v1"
        digest = Cell().raw(b"TOS-POP1").ref(challenge).hash
        signature = (
            self.primary(sign, digest, "pop") if role == 1 else self.rescue(sign, digest, "pop")
        )
        return chain(signature)

    def preparation(self, sign, request, context=b"TOS-RESCUE-FEE-PREP-v1", sk=None):
        assert context == b"TOS-RESCUE-FEE-PREP-v1"
        return chain(self.rescue(sign, request.hash, "preparation", sk))
