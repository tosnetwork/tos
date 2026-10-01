#!/usr/bin/env python3
"""Compile isolated native mutants, require their intended assertion, restore green."""

import argparse
import difflib
import hashlib
import json
import pathlib
import subprocess
import tempfile

parser = argparse.ArgumentParser()
parser.add_argument("--evidence", required=True, type=pathlib.Path)
args = parser.parse_args()
root = pathlib.Path(__file__).resolve().parents[3]
args.evidence.mkdir(parents=True, exist_ok=True)
cases = [
    (
        "enabled",
        "diagnostic-producer.h",
        "if (stats_.enabled.load(std::memory_order_acquire) == 0)\n      return false;",
        "if (false)\n      return false;",
        "diagnostic-producer.cpp",
        [],
        "stats.dropped == 0",
    ),
    (
        "sample",
        "diagnostic-producer.h",
        "if (ticket % sample_every_ != 0)",
        "if (false)",
        "diagnostic-producer.cpp",
        [],
        "stats.sampled_out == 4096",
    ),
    (
        "capacity",
        "diagnostic-producer.h",
        "if (count_ == capacity)",
        "if (false)",
        "diagnostic-producer.cpp",
        [],
        "!p->emit(builder) && built == 4096",
    ),
    (
        "sequence",
        "diagnostic-producer.h",
        "i < 8 && old != UINT64_MAX",
        "i < 8",
        "diagnostic-producer.cpp",
        [],
        "contention.reasons[2] == 1",
    ),
    (
        "peer-pid",
        "diagnostic-ipc.h",
        "creds.pid != peer_ || ",
        "",
        "diagnostic-ipc.cpp",
        ["bad-peer"],
        "diagnostic_stats.sent == 0 && diagnostic_stats.dropped > 0",
    ),
    (
        "socket-accounting",
        "diagnostic-ipc.h",
        "diagnostic_stats.drop(DiagnosticProducer::Drop::Socket);",
        "(void)0;",
        "diagnostic-ipc.cpp",
        [],
        "DiagnosticProducer::Drop::Socket)] > 0",
    ),
]
index = []
for name, header, before, after, fixture, arguments, needle in cases:
    with tempfile.TemporaryDirectory(prefix="nhm-c06-mutant-") as directory:
        work = pathlib.Path(directory)
        (work / "metrics").mkdir()
        for source in ("diagnostic-producer.h", "diagnostic-wire.h", "diagnostic-ipc.h"):
            (work / "metrics" / source).write_bytes((root / "metrics" / source).read_bytes())
        path = work / "metrics" / header
        original = path.read_text()
        assert original.count(before) == 1, (name, "nonunique mutation")
        binary = work / "test"
        test = root / "tools/node-health-monitor/tests/native" / fixture
        command = [
            "g++",
            "-std=c++20",
            "-O2",
            "-pthread",
            "-I" + str(work),
            str(test),
            "-o",
            str(binary),
        ]

        def build(label):
            result = subprocess.run(
                command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
            )
            (args.evidence / (name + "-" + label + "-compile.log")).write_text(result.stdout)
            assert result.returncode == 0, (name, label, result.stdout)

        def run(label):
            result = subprocess.run(
                [str(binary), *arguments],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=10,
            )
            (args.evidence / (name + "-" + label + ".log")).write_text(result.stdout)
            return result

        build("baseline")
        baseline = run("baseline")
        assert baseline.returncode == 0, (name, baseline.stdout)
        mutant = original.replace(before, after)
        patch = "".join(
            difflib.unified_diff(
                original.splitlines(keepends=True),
                mutant.splitlines(keepends=True),
                fromfile=header,
                tofile=header,
            )
        )
        (args.evidence / (name + ".patch")).write_text(patch)
        path.write_text(mutant)
        build("mutant")
        mutant_binary = hashlib.sha256(binary.read_bytes()).hexdigest()
        red = run("red")
        assert red.returncode != 0 and needle in red.stdout, (
            name,
            "missing intended assertion",
            red.stdout,
        )
        path.write_text(original)
        build("restored")
        green = run("green")
        assert green.returncode == 0, (name, green.stdout)
        index.append(
            dict(
                name=name,
                header=header,
                baseline_sha256=hashlib.sha256(original.encode()).hexdigest(),
                mutant_sha256=hashlib.sha256(mutant.encode()).hexdigest(),
                patch_sha256=hashlib.sha256(patch.encode()).hexdigest(),
                mutant_binary_sha256=mutant_binary,
                restored_binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
                compiled=True,
                red_exit=red.returncode,
                intended_assertion=needle,
                restored_exit=green.returncode,
            )
        )
        print(name + ": intended compiled assertion killed; restored natural0", flush=True)
(args.evidence / "index.json").write_text(json.dumps(index, indent=2) + "\n")
