import importlib.util
import json
import http.server
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path


PERF = Path(__file__).resolve().parents[1] / "perf"


def load(name):
    spec = importlib.util.spec_from_file_location(name, PERF / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


raw = load("raw_monotonic")
profiles = load("c09_profiles")


def ledger():
    return {role: {"status": "not_run"} for role in ("V", "edge", "M", "O", "A")}


class RawContractTest(unittest.TestCase):
    def test_cli_captures_real_local_get(self):
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"ok")

            def log_message(self, *_):
                pass

        server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / "raw.jsonl"
                subprocess.run([sys.executable, str(PERF / "raw_monotonic.py"),
                                f"http://127.0.0.1:{server.server_port}/", str(path), "--count", "2"], check=True)
                manifest = json.loads(path.with_suffix(".jsonl.manifest.json").read_text())
                self.assertEqual((manifest["requested"], manifest["retained"], manifest["dropped"]), (2, 2, 0))
                raw.verify_capture(path, manifest)
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

    def test_same_epoch_domain_duration_and_wall_clock_irrelevance(self):
        a = raw.Point("epoch", raw.CLOCK_ID, 100)
        b = raw.Point("epoch", raw.CLOCK_ID, 125)
        self.assertEqual(raw.duration_ns(a, b), 25)

    def test_reject_cross_process_or_clock_or_backwards(self):
        a = raw.Point("epoch", raw.CLOCK_ID, 100)
        for b in (raw.Point("other", raw.CLOCK_ID, 125),
                  raw.Point("epoch", "linux:CLOCK_MONOTONIC", 125),
                  raw.Point("epoch", raw.CLOCK_ID, 99),
                  raw.Point("epoch", raw.CLOCK_ID, 100 + raw.MAX_DURATION_NS + 1)):
            with self.subTest(b=b), self.assertRaises(ValueError):
                raw.duration_ns(a, b)

    def test_capacity_drop_and_hash_tamper(self):
        capture = raw.Capture("external_request_rtt", max_records=1, max_bytes=4096)
        self.assertTrue(capture.finish("local_probe", capture.start()))
        self.assertFalse(capture.finish("local_probe", capture.start()))
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "raw.jsonl"
            manifest = capture.write(path, ledger())
            self.assertEqual((manifest["attempted"], manifest["retained"], manifest["dropped"]), (2, 1, 1))
            raw.verify_capture(path, manifest)
            path.write_bytes(path.read_bytes() + b" ")
            with self.assertRaises(ValueError):
                raw.verify_capture(path, manifest)

    def test_record_identity_and_duration_tamper_even_with_new_hash(self):
        capture = raw.Capture("external_request_rtt")
        capture.finish("local_probe", capture.start())
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "raw.jsonl"
            manifest = capture.write(path, ledger())
            record = json.loads(path.read_text())
            record["finish"]["process_epoch"] = "other"
            altered = raw.canonical(record)
            path.write_bytes(altered)
            manifest["retained_bytes"] = len(altered)
            import hashlib
            manifest["evidence_sha256"] = hashlib.sha256(altered).hexdigest()
            with self.assertRaises(ValueError):
                raw.verify_capture(path, manifest)

    def test_missing_resource_ledger_rejected(self):
        capture = raw.Capture("external_request_rtt")
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError):
                capture.write(Path(tmp) / "raw.jsonl", {"V": {"status": "not_run"}})


class ProfileContractTest(unittest.TestCase):
    def test_freeze_complete_alternating_plan(self):
        order = []
        for workload in profiles.WORKLOADS:
            for round_index in range(3):
                names = list(profiles.PROFILES)
                if round_index % 2:
                    names.reverse()
                order.extend({"workload": workload, "round": round_index, "profile": name} for name in names)
        plan = {"profiles": profiles.PROFILES, "workloads": list(profiles.WORKLOADS),
                "warmup_seconds": 60, "window_seconds": 1800, "rounds": 3, "order": order,
                "population": {"nodes": ["n1"], "scopes": ["masterchain"]},
                "hashes": {key: "a" * 64 for key in profiles.REQUIRED_HASHES},
                "roles": {"n1": "validator"}, "effective_quotas": {"n1": "measured"},
                "method": {"sample_policy": "all", "noise_rule": "predeclared",
                           "instrument_cost": "paired", "comparison": "paired rounds"}}
        self.assertEqual(len(profiles.freeze_plan(plan)["plan_sha256"]), 64)
        plan["order"][6:12] = [{**row, "round": 1} for row in plan["order"][:6]]
        with self.assertRaises(ValueError):
            profiles.freeze_plan(plan)

    def test_unhooked_native_stages_and_synthetic_gate(self):
        evidence = profiles.empty_run_evidence("C")
        self.assertEqual(set(evidence["native_stages"].values()), {"not_run"})
        self.assertEqual(profiles.classify_comparison(real_node=False, rounds=3, window_seconds=1800,
            samples=1000, dropped=0, resolution_sufficient=True, noise_sufficient=True,
            cpu_regression=0, p99_regression=0, native_stage_verified=False,
            resources_complete=False, work_complete=False), "not_run")

    def test_inconclusive_and_fail_do_not_widen_limits(self):
        args = dict(real_node=True, rounds=3, window_seconds=1800, samples=1000, dropped=0,
                    resolution_sufficient=True, noise_sufficient=True, cpu_regression=0.005,
                    p99_regression=0.02, native_stage_verified=True,
                    resources_complete=True, work_complete=True)
        self.assertEqual(profiles.classify_comparison(**args), "eligible_for_supervisor_review")
        self.assertEqual(profiles.classify_comparison(**(args | {"native_stage_verified": False})), "inconclusive")
        self.assertEqual(profiles.classify_comparison(**(args | {"dropped": 1})), "inconclusive")
        self.assertEqual(profiles.classify_comparison(**(args | {"p99_regression": 0.031})), "fail")


if __name__ == "__main__":
    unittest.main()
