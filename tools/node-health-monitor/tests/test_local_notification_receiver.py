"""The receiver's accept path: one idle TCP connection must not block the
service entrance, and the handshake itself must be bounded in time."""

import json
import os
import select
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "local-notification-receiver.py"
TOKEN = "test-private-" + "a" * 32


def _free_port():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


@pytest.fixture
def receiver(tmp_path):
    if shutil.which("openssl") is None:
        pytest.skip("openssl is required to mint the throwaway certificate")
    cert, key, token = tmp_path / "cert.pem", tmp_path / "key.pem", tmp_path / "token"
    token.write_text(TOKEN)
    token.chmod(0o600)
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            str(key),
            "-out",
            str(cert),
            "-days",
            "1",
            "-subj",
            "/CN=localhost",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=True,
    )
    port = _free_port()
    server = subprocess.Popen(
        [
            sys.executable,
            str(SCRIPT),
            "--listen",
            f"127.0.0.1:{port}",
            "--cert-file",
            str(cert),
            "--key-file",
            str(key),
            "--token-file",
            str(token),
            "--journal",
            str(tmp_path / "journal"),
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    try:
        ready, _, _ = select.select([server.stderr], [], [], 5)
        assert ready, "receiver never announced readiness"
        line = server.stderr.readline()
        assert b"receiver listening" in line, line
        yield port
    finally:
        try:
            os.killpg(os.getpgid(server.pid), signal.SIGKILL)
        except ProcessLookupError:
            pass
        server.communicate(timeout=5)


def _post(port, token=TOKEN, timeout=1.0):
    data = json.dumps(
        {"incident": {}, "idempotency_key": "owned-test", "payload_hash": "a" * 64}
    ).encode()
    request = urllib.request.Request(
        f"https://127.0.0.1:{port}/v1/notifications",
        data=data,
        headers={"Authorization": f"Bearer {token}", "idempotency-key": "owned-test"},
    )
    context = ssl._create_unverified_context()
    try:
        with urllib.request.urlopen(request, context=context, timeout=timeout) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as error:
        return error.code, json.loads(error.read())


def test_valid_delivery_is_receipted_and_wrong_token_refused(receiver):
    status, body = _post(receiver)
    assert status == 200
    assert body == {"accepted": True, "idempotency_key": "owned-test", "payload_hash": "a" * 64}
    status, body = _post(receiver, token="wrong")
    assert status == 401 and body == {"accepted": False}


def test_idle_tcp_connection_does_not_block_other_deliveries(receiver):
    # A client that connects and never starts TLS used to sit inside accept()
    # with the synchronous handshake, so nobody else could be served.
    idle = socket.create_connection(("127.0.0.1", receiver), timeout=1)
    try:
        time.sleep(0.05)
        started = time.monotonic()
        status, _ = _post(receiver, timeout=1.0)
        elapsed = time.monotonic() - started
        assert status == 200
        assert elapsed < 1.0, f"delivery stalled behind an idle connection: {elapsed:.2f}s"
    finally:
        idle.close()


def test_idle_connection_is_closed_at_the_handshake_deadline(receiver):
    spec = __import__("importlib.util").util.spec_from_file_location("receiver_mod", SCRIPT)
    module = __import__("importlib.util").util.module_from_spec(spec)
    spec.loader.exec_module(module)
    deadline = module.HANDSHAKE_TIMEOUT_S
    idle = socket.create_connection(("127.0.0.1", receiver), timeout=deadline + 1)
    try:
        started = time.monotonic()
        try:
            closed = idle.recv(1) == b""
        except OSError:
            closed = True
        assert closed, "the server kept an idle connection open past the handshake deadline"
        assert time.monotonic() - started <= deadline + 1
    finally:
        idle.close()
