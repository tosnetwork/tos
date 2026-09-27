"""Offline end-to-end run of z01_final_capture.capture_node against a fake node.

The fake node is a real child process with the validator argv shape, a
harness-owned stderr pipe, a loopback control listener and a DB directory; the
RPC, console and proof checker are stand-ins. It exercises the exact call path
the live runner uses, including the window-start ordering and block_source.
"""

import asyncio
import base64
import hashlib
import importlib.util
import json
import os
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import types
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "test/tostester/src"))
SPEC = importlib.util.spec_from_file_location("z01_final_capture", ROOT / "scripts/z01_final_capture.py")
assert SPEC and SPEC.loader
z01 = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(z01)

HEIGHT = 20
WINDOW_END = 22
PARAM30 = b"param30-cell-boc"
PARAM30_HASH = hashlib.sha256(PARAM30).hexdigest()


def block_bytes(seq: int) -> bytes:
    return f"block-{seq}".encode() * 4


def exact(seq: int) -> dict:
    root = hashlib.sha256(b"root" + block_bytes(seq)).digest()
    file = hashlib.sha256(block_bytes(seq)).digest()
    return {"@type": "tos.blockIdExt", "workchain": -1, "shard": str(-(1 << 63)), "seqno": seq,
            "root_hash": base64.b64encode(root).decode(), "file_hash": base64.b64encode(file).decode()}


def marker(seq: int) -> bytes:
    ident = exact(seq)
    root = base64.b64decode(ident["root_hash"]).hex().upper()
    file = base64.b64decode(ident["file_hash"]).hex().upper()
    return (f"[ 3][t 2][2026-09-26 00:00:{seq:02d}.000000][BusRuntime.h:238] Published event "
            f"BlockFinalizedInMasterchain@0x1{{block=(-1,8000000000000000,{seq}):{root}:{file}}}\n").encode()


CHECKER = f"""#!{sys.executable}
import hashlib, sys
wc, shard, seqno, root, file, block, state, config, param = sys.argv[1:]
data = open(block, 'rb').read()
if hashlib.sha256(data).hexdigest() != file or hashlib.sha256(b'root' + data).hexdigest() != root:
    sys.stderr.write('Z01_CONFIG_PROOF_REJECT: block\\n'); sys.exit(1)
if open(state, 'rb').read() != b'state-' + seqno.encode():
    sys.stderr.write('Z01_CONFIG_PROOF_REJECT: state/config proof does not match the block ID\\n'); sys.exit(1)
cell = hashlib.sha256(open(param, 'rb').read()).hexdigest()
print(f'Z01_CONFIG_PROOF_OK seqno={{seqno}} root={{root}} file={{file}} param30={{cell}}')
"""


class FakeConsole:
    def __init__(self, binding: dict):
        self.binding = binding
        self.overrides: list = []

    def public_binding(self):
        return dict(self.binding)

    async def get_consensus_noncritical_params_overrides_with_raw(self):
        reply = json.dumps({"@type": "consensus.noncriticalParamsOverrideList",
                            "overrides": self.overrides}).encode()
        return types.SimpleNamespace(overrides=list(self.overrides)), b"{}", reply


class CaptureNodeOffline(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db = Path(self.temp.name) / "node0"
        self.db.mkdir()
        self.out = Path(self.temp.name) / "out"
        control = socket.socket()
        control.bind(("127.0.0.1", 0))
        self.console_port = control.getsockname()[1]
        control.close()
        self.global_config = self.db / "config.global.json"
        self.global_config.write_text("{}")
        server_id, client_id = b"\x11" * 32, b"\x22" * 32
        (self.db / "config.json").write_text(json.dumps({"control": [{
            "port": self.console_port, "id": base64.b64encode(server_id).decode(),
            "allowed": [{"id": base64.b64encode(client_id).decode()}]}]}))
        self.console = FakeConsole({"address": f"127.0.0.1:{self.console_port}",
                                    "server_key_id_hex": server_id.hex(),
                                    "client_key_id_hex": client_id.hex()})
        self.log = (self.db / "log").open("wb")
        self.log.write(b"startup line\n" + marker(HEIGHT - 2) + marker(HEIGHT - 1))
        self.log.flush()
        child = (f"import socket, time\ns = socket.socket()\ns.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n"
                 f"s.bind(('127.0.0.1', {self.console_port}))\ns.listen()\ntime.sleep(30)\n")
        self.process = subprocess.Popen(
            [sys.executable, "-c", child, "--db", ".", "--global-config", str(self.global_config),
             "--json-rpc-address", "127.0.0.1:1"],
            cwd=self.db, stderr=subprocess.PIPE, env={"PATH": os.environ.get("PATH", "/bin")})
        # Wait until the child's control socket is listening; fds of a starting
        # interpreter can vanish while being listed, so tolerate that.
        wanted = f"0100007F:{self.console_port:04X}"
        deadline = time.monotonic() + 5
        while not any(line.split()[1] == wanted and line.split()[3] == "0A"
                      for line in Path("/proc/net/tcp").read_text().splitlines()[1:]):
            self.assertLess(time.monotonic(), deadline, "fake node never listened")
            time.sleep(0.02)
        self.checker = Path(self.temp.name) / "checker"
        self.checker.write_text(CHECKER)
        self.checker.chmod(self.checker.stat().st_mode | stat.S_IXUSR)
        self.tip = HEIGHT - 1
        self.block_source_calls: list[int] = []

    def tearDown(self):
        self.process.terminate()
        self.process.wait(timeout=5)
        assert self.process.stderr is not None
        self.process.stderr.close()
        self.log.close()
        self.temp.cleanup()

    def node(self) -> dict:
        assert self.process.stderr is not None
        stat_raw = Path(f"/proc/{self.process.pid}/stat").read_bytes()
        exe = Path(os.readlink(f"/proc/{self.process.pid}/exe"))
        zero = exact(0)
        return {"name": "node0", "db_root": str(self.db), "governance_window_end_height": WINDOW_END,
                "global_config_path": str(self.global_config),
                "global_config_sha256": hashlib.sha256(self.global_config.read_bytes()).hexdigest(),
                "db_config_sha256": hashlib.sha256((self.db / "config.json").read_bytes()).hexdigest(),
                "pid": self.process.pid, "start_ticks": int(stat_raw.rsplit(b") ", 1)[1].split()[19]),
                "exe_sha256": hashlib.sha256(exe.read_bytes()).hexdigest(),
                "rpc_endpoint": "127.0.0.1:1",
                "stderr_pipe_inode": os.fstat(self.process.stderr.fileno()).st_ino,
                "harness_pid": os.getpid(),
                "log_stream_fds": {"input_fd": self.process.stderr.fileno(), "output_fd": self.log.fileno()},
                "console_endpoint": f"127.0.0.1:{self.console_port}",
                "zerostate_hashes": [base64.b64decode(zero["root_hash"]).hex(),
                                     base64.b64decode(zero["file_hash"]).hex()],
                "window_timeout_seconds": 20,
                "proof_checker_sha256": hashlib.sha256(self.checker.read_bytes()).hexdigest(),
                "param30_cell_hash": PARAM30_HASH, "block_bocs": {}}

    def rpc(self, endpoint: str, request: bytes):
        at = time.monotonic_ns()
        body = json.loads(request)
        method, params = body["method"], body["params"]
        if method == "getMasterchainInfo":
            result = {"last": exact(self.tip), "init": exact(0)}
        elif method == "getBlockHeader":
            result = {"id": exact(params["seqno"])}
        elif method == "getConfigParam":
            seq = params["seqno"]
            result = {"@type": "configInfo", "block_id": exact(seq),
                      "config": {"@type": "tvm.cell", "bytes": base64.b64encode(PARAM30).decode()},
                      "state_proof": base64.b64encode(b"state-" + str(seq).encode()).decode(),
                      "config_proof": base64.b64encode(b"config").decode()}
        else:
            raise AssertionError(method)
        response = json.dumps({"jsonrpc": "2.0", "id": body["id"], "result": result}).encode()
        return 200, response, at, time.monotonic_ns()

    def block_source(self, seq: int, full: tuple) -> dict:
        self.block_source_calls.append(seq)
        path = Path(self.temp.name) / f"fetched-{seq}.boc"
        path.write_bytes(block_bytes(seq))
        return {"path": str(path), "sha256": hashlib.sha256(block_bytes(seq)).hexdigest()}

    def finalize_later(self, delay: float = 0.3) -> threading.Thread:
        def run():
            for seq in range(HEIGHT, WINDOW_END + 1):
                time.sleep(delay)
                self.log.write(marker(seq))
                self.log.flush()
                self.tip = seq
        thread = threading.Thread(target=run)
        thread.start()
        return thread

    def capture(self, **kwargs) -> dict:
        return asyncio.run(z01.capture_node(self.node(), HEIGHT, self.out, self.console, self.checker,
                                            rpc=self.rpc, block_source=self.block_source, **kwargs))

    def test_full_window_passes_with_exact_block_source(self):
        thread = self.finalize_later()
        try:
            receipt = self.capture()
        finally:
            thread.join()
        self.assertTrue(receipt["passed"])
        self.assertEqual(sorted(receipt["full_ids"]), ["20", "21", "22"])
        self.assertEqual(self.block_source_calls, [20, 21, 22])
        self.assertTrue(all(row["exit"] == 0 for row in receipt["proofs"].values()))
        self.assertEqual(receipt["process_before"]["environment"]["names"], ["PATH"])
        rpc_order = [row["label"] for row in receipt["rpc"]]
        self.assertEqual(rpc_order[0], "masterchain-info")
        self.assertTrue((self.out / "receipt.json").is_file())

    def test_late_start_after_h_is_refused(self):
        self.log.write(marker(HEIGHT))
        self.log.flush()
        self.tip = HEIGHT
        with self.assertRaisesRegex(z01.EvidenceError, "native H marker predates"):
            self.capture()

    def test_block_source_with_other_bytes_is_refused(self):
        def wrong(seq, full):
            path = Path(self.temp.name) / f"wrong-{seq}.boc"
            path.write_bytes(b"other")
            return {"path": str(path), "sha256": hashlib.sha256(b"other").hexdigest()}
        self.block_source = wrong
        thread = self.finalize_later(0.1)
        try:
            with self.assertRaisesRegex(z01.EvidenceError, "raw block BOC differs"):
                self.capture()
        finally:
            thread.join()

    def test_override_file_created_mid_window_is_refused(self):
        def run():
            time.sleep(0.2)
            (self.db / "noncritical-params-overrides.json").write_text("{}")
            for seq in range(HEIGHT, WINDOW_END + 1):
                time.sleep(0.2)
                self.log.write(marker(seq))
                self.log.flush()
                self.tip = seq
        thread = threading.Thread(target=run)
        thread.start()
        try:
            with self.assertRaisesRegex(z01.EvidenceError, "override changed|override file is present"):
                self.capture()
        finally:
            thread.join()


if __name__ == "__main__":
    unittest.main()
