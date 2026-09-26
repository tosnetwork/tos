import asyncio
import json
import unittest

from tosapi import tos_api
from tostester.key import Key
from toslib.engine_console import EngineConsoleClient


class FakeRequest:
    def to_json(self):
        return '{"@type":"engine.validator.getConsensusNoncriticalParamsOverrides"}'


class FakeToslib:
    def __init__(self):
        self.request_bytes = None
        self.destroyed = 0

    def engine_console_request(self, console, request):
        self.request_bytes = request
        return 7

    def response_await_ready(self, response):
        return True

    def response_is_error(self, response):
        return False

    def response_get_response(self, response):
        return b'{"@type":"consensus.noncriticalParamsOverrideList","overrides":[]}'

    def response_destroy(self, response):
        self.destroyed += 1


class RawConsoleReceipt(unittest.TestCase):
    def test_public_binding_derived_from_actual_console_config(self):
        server = Key()
        client = Key()
        class Toslib:
            def engine_console_create(self, loop, config):
                return 1
            def engine_console_is_error(self, handle):
                return False
            def engine_console_destroy(self, handle):
                pass
        class Loop:
            loop = 0
        config = tos_api.EngineConsoleClient_config(
            address="127.0.0.1:26604", server_public_key=server.public_key,
            client_private_key=client.private_key)
        console = EngineConsoleClient(Toslib(), Loop(), config)
        try:
            binding = console.public_binding()
            self.assertEqual(binding["server_key_id_hex"], server.id.hex())
            self.assertEqual(binding["client_key_id_hex"], client.id.hex())
            self.assertNotIn(client.private_key.key.hex(), str(binding))
        finally:
            console.close()

    def test_exact_wire_bytes_and_existing_parsed_api(self):
        client = object.__new__(EngineConsoleClient)
        client._toslib = FakeToslib()
        client._console = 1
        try:
            parsed, request, response = asyncio.run(client.request_with_raw(FakeRequest()))
            self.assertEqual(request, client._toslib.request_bytes)
            self.assertEqual(response, b'{"@type":"consensus.noncriticalParamsOverrideList","overrides":[]}')
            self.assertEqual(parsed, json.loads(response))
            self.assertEqual(asyncio.run(client.request(FakeRequest())), parsed)
            self.assertEqual(client._toslib.destroyed, 2)
        finally:
            client._console = 0


if __name__ == "__main__":
    unittest.main()
