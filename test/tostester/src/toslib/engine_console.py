import json
import traceback
from typing import cast, final

from tonapi import tos_api

from tl import JSONSerializable, TLRequest

from .errors import LocalError, RemoteError
from .event_loop import ToslibEventLoop
from .toslib_cdll import ToslibCDLL


@final
class EngineConsoleClient:
    def __init__(
        self,
        toslib: ToslibCDLL,
        event_loop: ToslibEventLoop,
        config: tos_api.EngineConsoleClient_config,
    ):
        self._toslib = toslib
        self._event_loop = event_loop
        config_json = config.to_json().encode()
        self._console = toslib.engine_console_create(event_loop.loop, config_json)

        if toslib.engine_console_is_error(self._console):
            error_code = toslib.engine_console_get_error_code(self._console)
            error_message = toslib.engine_console_get_error_message(self._console).decode()
            toslib.engine_console_destroy(self._console)
            self._console = 0
            raise LocalError(error_code, error_message)

    def __del__(self):
        assert self._console == 0, (
            "EngineConsoleClient not destroyed. Call 'close' before destroying the object."
        )

    def close(self) -> None:
        if self._console == 0:
            return

        self._toslib.engine_console_destroy(self._console)
        self._console = 0

    def __enter__(self):
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: traceback.TracebackException | None,
    ):
        self.close()

    async def request(self, request: TLRequest) -> JSONSerializable:
        response = self._toslib.engine_console_request(self._console, request.to_json().encode())

        try:
            if not self._toslib.response_await_ready(response):
                continuation_id, future = self._event_loop.create_awaitable_future()
                if continuation_id is not None:
                    self._toslib.response_await_suspend(response, continuation_id)
                await future

            if self._toslib.response_is_error(response):
                error_code = self._toslib.response_get_error_code(response)
                error_message = self._toslib.response_get_error_message(response).decode()
                raise LocalError(error_code, error_message)

            response_json = self._toslib.response_get_response(response).decode()
            response_json = cast(JSONSerializable, json.loads(response_json))

            if (
                isinstance(response_json, dict)
                and response_json.get("@type", None) == "engine.validator.controlQueryError"
            ):
                error = tos_api.Engine_validator_controlQueryError.from_dict(response_json)
                raise RemoteError(error.code, error.message)

            return response_json
        finally:
            self._toslib.response_destroy(response)

    async def get_actor_stats(self) -> str:
        query = tos_api.Engine_validator_getActorTextStatsRequest()
        return query.parse_result(await self.request(query)).data

    async def get_consensus_noncritical_params_overrides(
        self,
    ) -> tos_api.Consensus_noncriticalParamsOverrideList:
        query = tos_api.Engine_validator_getConsensusNoncriticalParamsOverridesRequest()
        return query.parse_result(await self.request(query))

    async def set_consensus_noncritical_params_overrides(
        self, overrides: tos_api.Consensus_noncriticalParamsOverrideList
    ) -> None:
        query = tos_api.Engine_validator_setConsensusNoncriticalParamsOverridesRequest(overrides)
        _ = await self.request(query)
