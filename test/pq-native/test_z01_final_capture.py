import base64
import copy
import importlib.util
import os
import hashlib
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("z01_final_capture", ROOT / "scripts/z01_final_capture.py")
assert SPEC and SPEC.loader
z01 = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(z01)


def full_id(height: int, root: bytes = b"\x11" * 32) -> dict:
    return {"@type": "tos.blockIdExt", "workchain": -1, "shard": str(-(1 << 63)),
            "seqno": height, "root_hash": base64.b64encode(root).decode(),
            "file_hash": base64.b64encode(b"\x22" * 32).decode()}


def receipts() -> list[dict]:
    ids = {str(height): list(z01.block_id(full_id(height), height)) for height in (10, 11, 12, 13)}
    return [{"passed": True, "node": f"node{i}",
             "process_before": {"pid": 100 + i, "start_ticks": 1000 + i,
                                "cwd_dev": 1, "cwd_ino": 200 + i},
             "rpc": [{"endpoint": f"127.0.0.1:{2000 + i}"}], "full_ids": copy.deepcopy(ids),
             "native_log": {"dev": 1, "ino": 300 + i, "sha256": f"{i+1:064x}",
                            "pid": 100 + i, "start_ticks": 1000 + i},
             "native_stream": {"pipe_inode": 500 + i},
             "console_before": {"socket_inode": str(400 + i),
                                "address": f"127.0.0.1:{26600 + i}",
                                "server_key_id_hex": f"{i+1:064x}"},
             "zerostate": list(z01.block_id(full_id(0), 0))}
            for i in range(4)]


class FinalCaptureControls(unittest.TestCase):
    def test_exact_block_and_proofs_pass(self):
        header = {"id": full_id(10)}
        config = {"@type": "configInfo", "block_id": full_id(10),
                  "config": {"@type": "tvm.cell", "bytes": base64.b64encode(b"param").decode()},
                  "state_proof": base64.b64encode(b"state").decode(),
                  "config_proof": base64.b64encode(b"proof").decode()}
        exact, param, state, proof = z01.config_provenance(header, config, 10)
        self.assertEqual((exact[2], param, state, proof), (10, b"param", b"state", b"proof"))

        wrong = {**config, "block_id": full_id(10, b"\x33" * 32)}
        with self.assertRaisesRegex(z01.EvidenceError, "different full BlockIdExt"):
            z01.config_provenance(header, wrong, 10)
        missing = {**config, "state_proof": ""}
        with self.assertRaisesRegex(z01.EvidenceError, "empty Config30 or proof"):
            z01.config_provenance(header, missing, 10)
        with self.assertRaisesRegex(z01.EvidenceError, "missing full BlockIdExt"):
            z01.config_provenance(header, {k: v for k, v in config.items() if k != "block_id"}, 10)

    def test_four_distinct_processes_and_full_ids(self):
        good = receipts()
        self.assertTrue(z01.verify_cluster(good)["passed"])
        alias = receipts()
        alias[3]["process_before"]["cwd_ino"] = alias[0]["process_before"]["cwd_ino"]
        with self.assertRaisesRegex(z01.EvidenceError, "DB alias"):
            z01.verify_cluster(alias)
        conflict = receipts()
        conflict[3]["full_ids"]["11"][3] = "33" * 32
        with self.assertRaisesRegex(z01.EvidenceError, "conflicting full BlockIdExt"):
            z01.verify_cluster(conflict)
        gap = receipts()
        for row in gap:
            del row["full_ids"]["12"]
        with self.assertRaisesRegex(z01.EvidenceError, "missing common finalized heights"):
            z01.verify_cluster(gap)
        log_alias = receipts()
        log_alias[3]["native_log"]["sha256"] = log_alias[0]["native_log"]["sha256"]
        with self.assertRaisesRegex(z01.EvidenceError, "native log raw byte alias"):
            z01.verify_cluster(log_alias)
        wrong_generation = receipts()
        wrong_generation[3]["native_log"]["start_ticks"] += 1
        with self.assertRaisesRegex(z01.EvidenceError, "native log process generation mismatch"):
            z01.verify_cluster(wrong_generation)
        console_alias = receipts()
        console_alias[3]["console_before"]["server_key_id_hex"] = console_alias[0]["console_before"]["server_key_id_hex"]
        with self.assertRaisesRegex(z01.EvidenceError, "console address or server key alias"):
            z01.verify_cluster(console_alias)

    def test_override_watcher_detects_transient_file(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.assertEqual(z01.override_absence(root)["errno"], 2)
            watcher = z01.OverrideWatcher(root)
            self.assertGreaterEqual(watcher.watch, 0)
            target = root / "noncritical-params-overrides.json"
            target.write_text("{}")
            target.unlink()
            try:
                with self.assertRaisesRegex(z01.EvidenceError, "override changed"):
                    watcher.drain()
            finally:
                os.close(watcher.fd)

    def test_console_keys_and_socket_bound_to_target(self):
        binding = {"address": "127.0.0.1:26604", "server_key_id_hex": "11" * 32,
                   "client_key_id_hex": "22" * 32}
        config = {"control": [{"port": 26604,
                               "id": base64.b64encode(bytes.fromhex("11" * 32)).decode(),
                               "allowed": [{"id": base64.b64encode(bytes.fromhex("22" * 32)).decode()}]}]}
        import json
        tcp = b"sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n 0: 0100007F:67EC 00000000:0000 0A 0 0 0 0 0 999\n"
        # 0x67EC is 26604.
        raw = json.dumps(config).encode()
        self.assertEqual(z01.verify_console_binding(binding, raw, binding["address"], tcp,
                                                    {"8": "socket:[999]"})["socket_inode"], "999")
        wrong = {**binding, "server_key_id_hex": "33" * 32}
        with self.assertRaisesRegex(z01.EvidenceError, "keys differ"):
            z01.verify_console_binding(wrong, raw, binding["address"], tcp, {"8": "socket:[999]"})
        with self.assertRaisesRegex(z01.EvidenceError, "owned by another process"):
            z01.verify_console_binding(binding, raw, binding["address"], tcp,
                                       {"8": "socket:[1000]"})

    def test_process_stderr_pipe_binds_log_generation(self):
        with tempfile.TemporaryDirectory() as directory:
            db = Path(directory)
            config = db / "global.json"
            config.write_text("{}")
            raw = db / "raw"
            raw.mkdir()
            command = [sys.executable, "-c", "import time; time.sleep(10)",
                       "--db", ".", "--global-config", "global.json",
                       "--json-rpc-address", "127.0.0.1:27600"]
            clean_env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin")}
            process = subprocess.Popen(command, cwd=db, stderr=subprocess.PIPE, env=clean_env)
            try:
                assert process.stderr is not None
                pipe_inode = os.fstat(process.stderr.fileno()).st_ino
                executable = Path(os.readlink(f"/proc/{process.pid}/exe"))
                binary_sha = hashlib.sha256(executable.read_bytes()).hexdigest()
                snapshot = z01.process_snapshot(process.pid, db, binary_sha, raw, "valid",
                                                "127.0.0.1:27600", config, pipe_inode)
                self.assertEqual(snapshot["stderr_pipe_inode"], pipe_inode)
                self.assertEqual(snapshot["environment"]["names"], ["PATH"])
                self.assertTrue((raw / "valid-proc-environ.raw").is_file())
                with self.assertRaisesRegex(z01.EvidenceError, "stderr pipe differs"):
                    z01.process_snapshot(process.pid, db, binary_sha, raw, "wrong",
                                         "127.0.0.1:27600", config, pipe_inode + 1)
            finally:
                process.terminate()
                process.wait(timeout=5)
                process.stderr.close()

    def test_environment_refuses_local_runtime_knobs(self):
        self.assertEqual(z01.environment_policy(b"PATH=/bin\0HOME=/tmp\0")["names"], ["HOME", "PATH"])
        self.assertEqual(z01.environment_policy(b"")["names"], [])
        for raw in (b"PATH=/bin\0TOS_SIMPLEX_CANDIDATE_RETENTION_SLOTS=9\0",
                    b"TOS_ROCKSDB_BLOCK_CACHE_SIZE=1\0",
                    b"TOS_TEST_ORIGIN_TRANSIENT_FAILURES=1\0"):
            with self.assertRaisesRegex(z01.EvidenceError, "local runtime knobs"):
                z01.environment_policy(raw)
        with self.assertRaisesRegex(z01.EvidenceError, "malformed process environment"):
            z01.environment_policy(b"PATH=/bin")
        with self.assertRaisesRegex(z01.EvidenceError, "duplicate"):
            z01.environment_policy(b"A=1\0A=2\0")

    def test_process_snapshot_refuses_knob_in_child_environment(self):
        with tempfile.TemporaryDirectory() as directory:
            db = Path(directory)
            config = db / "global.json"
            config.write_text("{}")
            raw = db / "raw"
            raw.mkdir()
            command = [sys.executable, "-c", "import time; time.sleep(10)",
                       "--db", ".", "--global-config", "global.json",
                       "--json-rpc-address", "127.0.0.1:27601"]
            env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                   "TOS_SIMPLEX_CANDIDATE_RESOLVE_MAX_ATTEMPTS": "1"}
            process = subprocess.Popen(command, cwd=db, stderr=subprocess.PIPE, env=env)
            try:
                assert process.stderr is not None
                pipe_inode = os.fstat(process.stderr.fileno()).st_ino
                executable = Path(os.readlink(f"/proc/{process.pid}/exe"))
                binary_sha = hashlib.sha256(executable.read_bytes()).hexdigest()
                with self.assertRaisesRegex(z01.EvidenceError, "local runtime knobs"):
                    z01.process_snapshot(process.pid, db, binary_sha, raw, "knob",
                                         "127.0.0.1:27601", config, pipe_inode)
                self.assertTrue((raw / "knob-proc-environ.raw").is_file())
            finally:
                process.terminate()
                process.wait(timeout=5)
                process.stderr.close()

    def test_harness_streamer_fd_joins_child_pipe_and_raw_log(self):
        with tempfile.TemporaryDirectory() as directory:
            db = Path(directory)
            log = (db / "log").open("wb")
            other = (db / "other").open("wb")
            reader, writer = os.pipe()
            try:
                pipe_inode = os.fstat(reader).st_ino
                log_stat = os.fstat(log.fileno())
                node = {"harness_pid": os.getpid(),
                        "log_stream_fds": {"input_fd": reader, "output_fd": log.fileno()}}
                source = {"dev": log_stat.st_dev, "ino": log_stat.st_ino}
                process = {"stderr_pipe_inode": pipe_inode}
                self.assertEqual(z01.log_stream_binding(node, source, process)["pipe_inode"], pipe_inode)
                wrong_writer = {**node, "log_stream_fds": {**node["log_stream_fds"],
                                                            "output_fd": other.fileno()}}
                with self.assertRaisesRegex(z01.EvidenceError, "writes another file"):
                    z01.log_stream_binding(wrong_writer, source, process)
                with self.assertRaisesRegex(z01.EvidenceError, "reads another PID pipe"):
                    z01.log_stream_binding(node, source, {"stderr_pipe_inode": pipe_inode + 1})
            finally:
                os.close(reader)
                os.close(writer)
                log.close()
                other.close()

    def test_governance_watch_starts_before_h(self):
        def marker(h):
            return (f"[2026-09-25 20:00:00.000000] BlockFinalizedInMasterchain "
                    f"{{block=(-1,8000000000000000,{h}):{'11'*32}:{'22'*32}}}\n").encode()
        initial = marker(9)
        self.assertEqual(z01.require_window_start(initial, full_id(9), 10)[2], 9)
        with self.assertRaisesRegex(z01.EvidenceError, "native H marker predates"):
            z01.require_window_start(initial + marker(10), full_id(9), 10)
        with self.assertRaisesRegex(z01.EvidenceError, "lacks pre-window"):
            z01.require_window_start(b"unrelated log\n", full_id(9), 10)
        with self.assertRaisesRegex(z01.EvidenceError, "RPC H tip predates"):
            z01.require_window_start(initial, full_id(10), 10)


if __name__ == "__main__":
    unittest.main()
