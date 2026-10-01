"""Local controls for bounded raw capture; synthetic output is not C09 acceptance."""

import hashlib
import http.server
import json
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

PERF = Path(__file__).resolve().parents[1] / "perf"
sys.path.insert(0, str(PERF))
import c09_profiles as profiles  # noqa: E402 -- importable only once perf/ is on the path
import raw_monotonic as raw  # noqa: E402


def plan():
    order = []
    for workload in profiles.WORKLOADS:
        for round_index in range(3):
            names = list("ABCDEF")
            if round_index % 2:
                names.reverse()
            order.extend(
                {"workload": workload, "round": round_index, "profile": name} for name in names
            )
    return {
        "profiles": profiles.expected_profiles(False),
        "workloads": list(profiles.WORKLOADS),
        "warmup_seconds": 60,
        "window_seconds": 1800,
        "rounds": 3,
        "order": order,
        "population": {"nodes": ["fixture"], "scopes": ["masterchain"]},
        "hashes": {k: "a" * 64 for k in profiles.REQUIRED_HASHES},
        "roles": {"fixture": "validator"},
        "effective_quotas": {"fixture": {"queries": 0}},
        "method": {
            "sample_policy": "all_attempts",
            "noise_rule": "predeclared",
            "instrument_cost": "paired",
            "comparison": "alternating_rounds",
            "outcome_policy": "retain_all",
        },
        "cache_only_path": "/cached",
    }


def capture(path, requested=2, max_records=raw.MAX_RECORDS):
    return raw.Capture(
        path,
        plan_sha256=profiles.freeze_plan(plan())["plan_sha256"],
        profile="A",
        workload="normal",
        round_index=0,
        requested=requested,
        max_records=max_records,
    )


class Fixture(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != "/cached":
            self.send_error(404)
        elif self.server.mode == "redirect":
            self.send_response(302)
            self.send_header("Location", "http://example.com/")
            self.end_headers()
        else:
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"x")

    def log_message(self, *_):
        pass


class RawTest(unittest.TestCase):
    def test_plan_freezes_all_toggles_and_schedule(self):
        good = plan()
        self.assertEqual(len(profiles.freeze_plan(good)["plan_sha256"]), 64)
        for altered in (
            good
            | {
                "profiles": {
                    **good["profiles"],
                    "E": {**good["profiles"]["E"], "diagnostics": None},
                }
            },
            good | {"order": good["order"][:-1]},
            good | {"window_seconds": 1799},
            good | {"cache_only_path": "/cached?q=1"},
        ):
            with self.subTest(altered=altered.keys()), self.assertRaises(ValueError):
                profiles.freeze_plan(altered)
        evidence = profiles.empty_run_evidence("C")
        self.assertEqual(set(evidence["native_stages"].values()), {"not_run"})
        self.assertEqual(evidence["p99_regression"], "not_run")
        self.assertEqual(set(evidence["resources"].values()), {"not_run"})

    def test_clock_identity_and_canonical_decimal(self):
        p = raw.Point("epoch", "domain", raw.CLOCK_NAME, "100")
        self.assertEqual(
            raw.duration_ns(p, raw.Point("epoch", "domain", raw.CLOCK_NAME, "125")), "25"
        )
        for other in (
            raw.Point("other", "domain", raw.CLOCK_NAME, "125"),
            raw.Point("epoch", "other", raw.CLOCK_NAME, "125"),
            raw.Point("epoch", "domain", "CLOCK_MONOTONIC", "125"),
            raw.Point("epoch", "domain", raw.CLOCK_NAME, "99"),
            raw.Point("epoch", "domain", raw.CLOCK_NAME, "0100"),
            raw.Point("epoch", "domain", raw.CLOCK_NAME, str(100 + raw.MAX_DURATION_NS + 1)),
        ):
            with self.subTest(other=other), self.assertRaises(ValueError):
                raw.duration_ns(p, other)

    def test_real_owned_loopback_success_and_http_error(self):
        server = http.server.HTTPServer(("127.0.0.1", 0), Fixture)
        server.mode = "ok"
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                plan_path = root / "plan.json"
                plan_path.write_text(json.dumps(plan()))
                for mode in ("ok", "redirect"):
                    server.mode = mode
                    output = root / f"{mode}.jsonl"
                    result = subprocess.run(
                        [
                            sys.executable,
                            str(PERF / "raw_monotonic.py"),
                            "--plan",
                            str(plan_path),
                            "--profile",
                            "A",
                            "--workload",
                            "normal",
                            "--round",
                            "0",
                            "--url",
                            f"http://127.0.0.1:{server.server_port}/cached",
                            "--output",
                            str(output),
                            "--count",
                            "2",
                        ],
                        capture_output=True,
                        text=True,
                        timeout=10,
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)
                    manifest = raw.verify_capture(output)
                    self.assertEqual(
                        (manifest["requested"], manifest["retained"], manifest["dropped"]),
                        (2, 2, 0),
                    )
                    rows = [json.loads(line) for line in output.read_text().splitlines()]
                    self.assertEqual([row["seq"] for row in rows], [1, 2])
                    self.assertEqual(
                        {row["outcome"] for row in rows}, {"ok" if mode == "ok" else "http_error"}
                    )
                    self.assertEqual({row["population"] for row in rows}, {raw.POPULATION})
                    self.assertEqual(
                        {row["clock_domain_id"] for row in rows}, {manifest["clock_domain_id"]}
                    )
                    self.assertEqual(output.stat().st_mode & 0o777, 0o600)
        finally:
            server.shutdown()
            server.server_close()
            worker.join()

    def test_loopback_gate_refusal_and_capacity_are_population_rows(self):
        for url in (
            "http://example.com:80/cached",
            "http://localhost:1/cached",
            "http://127.0.0.1:1/other",
            "http://127.0.0.1:1/cached?q=1",
            "https://127.0.0.1:1/cached",
        ):
            with self.subTest(url=url), self.assertRaises(ValueError):
                raw._loopback_target(url, "/cached")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "raw.jsonl"
            c = capture(path, requested=2, max_records=1)
            self.assertTrue(c.finish(c.start(), "error"))
            self.assertFalse(c.finish(c.start(), "timeout"))
            manifest = c.close()
            self.assertEqual(
                (manifest["attempted"], manifest["retained"], manifest["dropped"]), (2, 1, 1)
            )
            with self.assertRaisesRegex(ValueError, "incomplete"):
                raw.verify_capture(path)
            self.assertFalse(raw.verify_capture(path, require_complete=False)["complete"])
            with self.assertRaises(FileExistsError):
                capture(path)

    def test_actual_refusal_and_timeout_outcomes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            server = http.server.HTTPServer(("127.0.0.1", 0), Fixture)
            unused_port = server.server_port
            server.server_close()
            self.assertEqual(raw._probe("127.0.0.1", unused_port, "/cached", 0.2), "error")

            class Slow(http.server.BaseHTTPRequestHandler):
                def do_GET(self):
                    time.sleep(0.2)

                def log_message(self, *_):
                    pass

            slow = http.server.HTTPServer(("127.0.0.1", 0), Slow)
            worker = threading.Thread(target=slow.serve_forever, daemon=True)
            worker.start()
            try:
                self.assertEqual(
                    raw._probe("127.0.0.1", slow.server_port, "/cached", 0.05), "timeout"
                )
            finally:
                slow.shutdown()
                slow.server_close()
                worker.join()
            for outcome in ("error", "timeout"):
                path = root / (outcome + ".jsonl")
                c = capture(path, requested=1)
                c.finish(c.start(), outcome)
                c.close()
                manifest = raw.verify_capture(path)
                self.assertTrue(manifest["complete"])
                self.assertEqual(json.loads(path.read_text())["outcome"], outcome)

    def test_tamper_missing_manifest_sequence_and_domain(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "raw.jsonl"
            c = capture(path)
            c.finish(c.start(), "ok")
            c.finish(c.start(), "error")
            c.close()
            raw.verify_capture(path)
            manifest_path = Path(str(path) + ".manifest.json")
            original = path.read_bytes()
            manifest = json.loads(manifest_path.read_text())
            for field, value in (
                ("seq", 3),
                ("duration_ns", "00"),
                ("population", "wrong"),
                ("clock_domain_id", "another-domain"),
                ("finish_ns", "0"),
            ):
                rows = [json.loads(line) for line in original.splitlines()]
                rows[0][field] = value
                altered = b"".join(raw.canonical(row) for row in rows)
                path.write_bytes(altered)
                changed = dict(
                    manifest,
                    retained_bytes=len(altered),
                    raw_sha256=hashlib.sha256(altered).hexdigest(),
                )
                manifest_path.write_bytes(raw.canonical(changed))
                with self.subTest(field=field), self.assertRaises(ValueError):
                    raw.verify_capture(path)
            path.write_bytes(original)
            manifest_path.unlink()
            with self.assertRaisesRegex(ValueError, "missing"):
                raw.verify_capture(path)

    def test_invalid_middle_attempt_keeps_raw_sequence_gap_visible(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "raw.jsonl"
            c = capture(path, requested=3)
            c.finish(c.start(), "ok")
            point = c.start()
            foreign = raw.Point(
                "other-epoch", point.clock_domain_id, point.clock_name, point.monotonic_ns
            )
            with self.assertRaises(ValueError):
                c.finish(foreign, "error")
            c.finish(c.start(), "timeout")
            manifest = c.close()
            self.assertEqual(
                (manifest["attempted"], manifest["retained"], manifest["invalid"]), (3, 2, 1)
            )
            self.assertEqual(
                [json.loads(line)["seq"] for line in path.read_text().splitlines()], [1, 3]
            )
            self.assertFalse(raw.verify_capture(path, require_complete=False)["complete"])
            with self.assertRaisesRegex(ValueError, "incomplete"):
                raw.verify_capture(path)

    def test_isolated_guard_mutants_turn_red(self):
        source = (PERF / "raw_monotonic.py").read_text()
        old = (
            "        or start.clock_domain_id != finish.clock_domain_id\n"
            "        or not start.clock_domain_id\n"
        )
        self.assertEqual(source.count(old), 1)
        mutant = source.replace(old, "        or False\n", 1)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "raw_monotonic.py").write_text(mutant)
            (root / "c09_profiles.py").write_text((PERF / "c09_profiles.py").read_text())
            program = (
                "import raw_monotonic as r\n"
                "a=r.Point('e','d1',r.CLOCK_NAME,'1')\n"
                "b=r.Point('e','d2',r.CLOCK_NAME,'2')\n"
                "assert r.duration_ns(a,b)=='1'\n"
            )
            compiled = subprocess.run(
                [sys.executable, "-m", "py_compile", str(root / "raw_monotonic.py")],
                capture_output=True,
            )
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            result = subprocess.run(
                [sys.executable, "-c", program], cwd=root, capture_output=True, text=True
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            original = subprocess.run(
                [sys.executable, "-c", program], cwd=PERF, capture_output=True
            )
            self.assertNotEqual(original.returncode, 0)


if __name__ == "__main__":
    unittest.main()
