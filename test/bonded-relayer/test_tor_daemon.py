"""Require installed Tor; validate both deployment profiles without public traffic."""

import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools/bonded-relayer"))
from relay_core import Refused  # noqa: E402
from test_tor_transport import ORIGIN, read_exact  # noqa: E402
from tor_transport import OnionEndpoint, TorProxy  # noqa: E402


class TorDaemonTests(unittest.TestCase):
    def test_real_daemon_validates_profiles_isolates_socks_and_refuses_without_network(self):
        tor = shutil.which("tor")
        self.assertIsNotNone(tor, "install Tor; this integration gate must not skip")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with socket.socket() as probe:
                probe.bind(("127.0.0.1", 0))
                port = probe.getsockname()[1]
            for role in ("client", "service"):
                config = (ROOT / f"tools/bonded-relayer/tor/{role}.torrc.example").read_text()
                config = config.replace(f"/var/lib/tor/br1-{role}", str(root / role))
                config = config.replace("127.0.0.1:9050", f"127.0.0.1:{port}")
                path = root / f"{role}.torrc"
                path.write_text(config + "\nDisableNetwork 1\n")
                result = subprocess.run(
                    [tor, "--verify-config", "-f", str(path)], capture_output=True, timeout=15
                )
                self.assertEqual(result.returncode, 0, result.stderr.decode())
            process = subprocess.Popen(
                [
                    tor,
                    "-f",
                    str(root / "client.torrc"),
                    "--DisableNetwork",
                    "0",
                    "--ReachableAddresses",
                    "reject *",
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            try:
                deadline = time.monotonic() + 10
                while True:
                    self.assertIsNone(process.poll(), "Tor exited before SOCKS became available")
                    try:
                        sock = socket.create_connection(("127.0.0.1", port), timeout=0.2)
                        break
                    except OSError:
                        if time.monotonic() >= deadline:
                            self.fail("Tor SOCKS did not start")
                        time.sleep(0.05)
                with sock:
                    sock.settimeout(2)
                    sock.sendall(b"\x05\x01\x02")
                    self.assertEqual(read_exact(sock, 2), b"\x05\x02")
                    sock.sendall(b"\x01\x03abc\x03def")
                    self.assertEqual(read_exact(sock, 2), b"\x01\x00")
                    # A daemon configured for onions must reject clearnet too.
                    sock.sendall(b"\x05\x01\x00\x03\x0bexample.com\x00\x50")
                    self.assertNotEqual(read_exact(sock, 4)[1], 0)
                start = time.monotonic()
                with self.assertRaises((Refused, OSError)):
                    TorProxy(port).connect(OnionEndpoint.parse(ORIGIN), start + 1)
                self.assertLess(time.monotonic() - start, 2)
            finally:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
            self.assertIsNotNone(process.returncode)


if __name__ == "__main__":
    unittest.main()
