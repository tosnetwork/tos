# pyright: reportAny=false, reportUnknownArgumentType=false

import asyncio
import json
from unittest.mock import Mock

import pytest
from tonapi import tos_api

from toslib import EngineConsoleClient, LocalError, RemoteError

MOCK_LOOP_PTR = 12345
MOCK_CONSOLE_PTR = 67890
MOCK_RESPONSE_PTR = 11111
MOCK_CONTINUATION_ID = 42


@pytest.fixture
def mock_toslib():
    toslib = Mock()
    toslib.engine_console_create = Mock(return_value=MOCK_CONSOLE_PTR)
    toslib.engine_console_destroy = Mock()
    toslib.engine_console_is_error = Mock(return_value=False)
    toslib.engine_console_get_error_code = Mock()
    toslib.engine_console_get_error_message = Mock()
    toslib.engine_console_request = Mock(return_value=MOCK_RESPONSE_PTR)
    toslib.response_destroy = Mock()
    toslib.response_await_ready = Mock(return_value=True)
    toslib.response_await_suspend = Mock()
    toslib.response_is_error = Mock(return_value=False)
    toslib.response_get_error_code = Mock()
    toslib.response_get_error_message = Mock()
    toslib.response_get_response = Mock(return_value=b'{"@type": "ok"}')
    return toslib


@pytest.fixture
def mock_event_loop():
    event_loop = Mock()
    event_loop.loop = MOCK_LOOP_PTR
    event_loop.create_awaitable_future = Mock()
    return event_loop


@pytest.fixture
def config():
    return tos_api.EngineConsoleClient_config(address="127.0.0.1:1234")


@pytest.mark.asyncio
async def test_init_success(
    mock_toslib: Mock, mock_event_loop: Mock, config: tos_api.EngineConsoleClient_config
):
    client = EngineConsoleClient(mock_toslib, mock_event_loop, config)

    mock_toslib.engine_console_create.assert_called_once_with(
        MOCK_LOOP_PTR, config.to_json().encode()
    )
    mock_toslib.engine_console_is_error.assert_called_once_with(MOCK_CONSOLE_PTR)

    client.close()

    mock_toslib.engine_console_destroy.assert_called_once_with(MOCK_CONSOLE_PTR)


@pytest.mark.asyncio
async def test_init_error(
    mock_toslib: Mock, mock_event_loop: Mock, config: tos_api.EngineConsoleClient_config
):
    mock_toslib.engine_console_is_error = Mock(return_value=True)
    mock_toslib.engine_console_get_error_code = Mock(return_value=500)
    mock_toslib.engine_console_get_error_message = Mock(return_value=b"Connection failed")

    with pytest.raises(LocalError, match="Connection failed") as exc_info:
        _ = EngineConsoleClient(mock_toslib, mock_event_loop, config)

    assert exc_info.value.code == 500
    assert exc_info.value.message == "Connection failed"

    mock_toslib.engine_console_destroy.assert_called_once_with(MOCK_CONSOLE_PTR)


@pytest.mark.asyncio
async def test_context_manager(
    mock_toslib: Mock, mock_event_loop: Mock, config: tos_api.EngineConsoleClient_config
):
    with EngineConsoleClient(mock_toslib, mock_event_loop, config):
        pass

    mock_toslib.engine_console_destroy.assert_called_once_with(MOCK_CONSOLE_PTR)


@pytest.mark.asyncio
async def test_aclose_idempotent(
    mock_toslib: Mock, mock_event_loop: Mock, config: tos_api.EngineConsoleClient_config
):
    client = EngineConsoleClient(mock_toslib, mock_event_loop, config)

    client.close()
    client.close()

    mock_toslib.engine_console_destroy.assert_called_once()


@pytest.mark.asyncio
async def test_request_synchronous(
    mock_toslib: Mock, mock_event_loop: Mock, config: tos_api.EngineConsoleClient_config
):
    mock_toslib.response_await_ready = Mock(return_value=True)
    response_data = {"@type": "engine.validator.success", "data": "test"}
    mock_toslib.response_get_response = Mock(return_value=json.dumps(response_data).encode())

    with EngineConsoleClient(mock_toslib, mock_event_loop, config) as client:
        request = tos_api.Engine_validator_getConfigRequest()
        result = await client.request(request)

        mock_toslib.engine_console_request.assert_called_once_with(
            MOCK_CONSOLE_PTR, request.to_json().encode()
        )

        mock_toslib.response_await_ready.assert_called_once_with(MOCK_RESPONSE_PTR)
        mock_toslib.response_await_suspend.assert_not_called()
        mock_toslib.response_destroy.assert_called_once_with(MOCK_RESPONSE_PTR)

        assert result == response_data


@pytest.mark.asyncio
async def test_request_asynchronous(
    mock_toslib: Mock, mock_event_loop: Mock, config: tos_api.EngineConsoleClient_config
):
    mock_toslib.response_await_ready = Mock(return_value=False)
    response_data = {"@type": "engine.validator.success", "data": "test"}
    mock_toslib.response_get_response = Mock(return_value=json.dumps(response_data).encode())

    future = asyncio.get_event_loop().create_future()
    future.set_result(None)
    mock_event_loop.create_awaitable_future = Mock(return_value=(MOCK_CONTINUATION_ID, future))

    with EngineConsoleClient(mock_toslib, mock_event_loop, config) as client:
        request = tos_api.Engine_validator_getConfigRequest()
        result = await client.request(request)

        mock_toslib.response_await_suspend.assert_called_once_with(
            MOCK_RESPONSE_PTR, MOCK_CONTINUATION_ID
        )
        mock_toslib.response_destroy.assert_called_once_with(MOCK_RESPONSE_PTR)

        assert result == response_data


@pytest.mark.asyncio
async def test_request_local_error(
    mock_toslib: Mock, mock_event_loop: Mock, config: tos_api.EngineConsoleClient_config
):
    mock_toslib.response_await_ready = Mock(return_value=True)
    mock_toslib.response_is_error = Mock(return_value=True)
    mock_toslib.response_get_error_code = Mock(return_value=404)
    mock_toslib.response_get_error_message = Mock(return_value=b"Not found")

    with EngineConsoleClient(mock_toslib, mock_event_loop, config) as client:
        request = tos_api.Engine_validator_getConfigRequest()

        with pytest.raises(LocalError, match="Not found") as exc_info:
            _ = await client.request(request)

        assert exc_info.value.code == 404
        assert exc_info.value.message == "Not found"

        mock_toslib.response_destroy.assert_called_once_with(MOCK_RESPONSE_PTR)


@pytest.mark.asyncio
async def test_request_remote_error(
    mock_toslib: Mock, mock_event_loop: Mock, config: tos_api.EngineConsoleClient_config
):
    mock_toslib.response_await_ready = Mock(return_value=True)
    error_response = {
        "@type": "engine.validator.controlQueryError",
        "code": 400,
        "message": "Invalid query",
    }
    mock_toslib.response_get_response = Mock(return_value=json.dumps(error_response).encode())

    with EngineConsoleClient(mock_toslib, mock_event_loop, config) as client:
        request = tos_api.Engine_validator_getConfigRequest()

        with pytest.raises(RemoteError, match="Invalid query") as exc_info:
            _ = await client.request(request)

        assert exc_info.value.code == 400
        assert exc_info.value.message == "Invalid query"

        mock_toslib.response_destroy.assert_called_once_with(MOCK_RESPONSE_PTR)
