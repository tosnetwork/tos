#!/usr/bin/env python3
"""Rebuild targeted codec mutations and require their specific semantic failures."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument("--target-dir", type=Path, required=True)
    parser.add_argument("--native-tool", type=Path, required=True)
    parser.add_argument("--container")
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--control", action="append", default=[])
    args = parser.parse_args()
    root = args.checkout.resolve()
    out = args.output_dir.resolve()
    out.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, TOKIO_WORKER_THREADS="2", RAYON_NUM_THREADS="2")
    result = []

    def run(command: list[str], name: str) -> subprocess.CompletedProcess[str]:
        done = subprocess.run(
            command,
            cwd=root,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=900,
        )
        (out / f"{name}.log").write_text(done.stdout)
        return done

    def cargo(package: str, test: str, integration: str | None = None) -> list[str]:
        command = [
            "cargo",
            "test",
            "--manifest-path",
            str(root / "tosctl/src/Cargo.toml"),
            "-p",
            package,
        ]
        command += ["--test", integration] if integration else ["--lib"]
        return command + [
            test,
            "--locked",
            "-j",
            "2",
            "--target-dir",
            str(args.target_dir.resolve()),
            "--",
            "--exact",
        ]

    def native(arguments: list[str]) -> list[str]:
        prefix = ["docker", "exec", "-w", str(root), args.container] if args.container else []
        return prefix + [str(args.native_tool.resolve()), *arguments]

    def mutate(name: str, relative: str, change, command: list[str], marker: str) -> None:
        if args.control and name not in args.control:
            return
        green = run(command, name + "-before")
        if green.returncode != 0 or "running 1 test" not in green.stdout:
            raise RuntimeError(f"{name}: positive setup did not execute one passing test")
        path = root / relative
        original = path.read_bytes()
        text = original.decode()
        modified = change(text)
        if modified == text:
            raise RuntimeError(f"{name}: stale mutation anchor")
        try:
            path.write_text(modified)
            red = run(command, name + "-red")
            if (
                red.returncode == 0
                or "running 1 test" not in red.stdout
                or marker not in red.stdout
            ):
                raise RuntimeError(
                    f"{name}: intended assertion did not fail; see {out / (name + '-red.log')}"
                )
        finally:
            path.write_bytes(original)
        restored = run(command, name + "-restored")
        if restored.returncode != 0 or "running 1 test" not in restored.stdout:
            raise RuntimeError(f"{name}: restoration is not green")
        result.append(
            {
                "name": name,
                "source": relative,
                "sha256": hashlib.sha256(original).hexdigest(),
                "red_exit": red.returncode,
                "restored_exit": restored.returncode,
                "marker": marker,
            }
        )
        print(f"TL_CONTROL_OK {name}", flush=True)
        (out / "result.json").write_text(json.dumps(result, indent=2) + "\n")

    def replacement(old: str, new: str):
        def apply(text: str) -> str:
            if text.count(old) != 1:
                raise RuntimeError(f"expected exactly one control anchor: {old}")
            return text.replace(old, new, 1)

        return apply

    mutate(
        "grouped-type",
        "tosctl/src/tl/codegen/src/lib.rs",
        replacement("            | (sym(b'(') * call(ty) - sym(b')'))\n", ""),
        cargo("tl_codegen", "tests::grouped_types_keep_wire_kind_and_constructor_id"),
        "valid grouped declaration",
    )
    mutate(
        "input-redirect",
        "tosctl/src/tl/codegen/src/input.rs",
        replacement("if file.canonicalize()? != file {", "if false {"),
        cargo("tl_codegen", "input::tests::authoritative_schema_symlink_is_refused"),
        "TL_REDIRECT_REFUSED",
    )
    mutate(
        "stale-module",
        "tosctl/src/tl/codegen/src/input.rs",
        replacement("fs::remove_file(previous)?;", "let _ = previous;"),
        cargo("tl_codegen", "input::tests::fixed_repository_inputs_and_regeneration"),
        "TL_STALE_MODULE",
    )
    values = "test/tl-cli/values.rs"
    import re

    def swap_fields(text: str) -> str:
        first = re.search(r"last_ping_at: ([^,\n]+)", text)
        second = re.search(r"last_ping_time: ([^,\n]+)", text)
        if not first or not second or first[1] == second[1]:
            raise RuntimeError("same-width field oracle is not sensitive")
        return text.replace(first[0], "last_ping_at: " + second[1], 1).replace(
            second[0], "last_ping_time: " + first[1], 1
        )

    mutate(
        "same-width-fields",
        values,
        swap_fields,
        cargo("tl_api", "native_cli_wire_fields_and_reverse_encoding", "cli_wire_parity"),
        "CLI_WIRE_FIELDS",
    )
    mutate(
        "retired-registration",
        "tosctl/src/tl/api/src/tos/dynamic.rs",
        replacement(
            "map (| d | (d . id , d)) . collect ()",
            "map (| d | (d . id , d)) . chain(std::iter::once((0x46efae62, &ALL_DESERIALIZERS[0]))) . collect ()",
        ),
        cargo("tl_api", "retired_stream_constructor_is_not_registered", "cli_wire_parity"),
        "RETIRED_STREAM_REGISTERED",
    )
    adapter_test = "client_adnl::cli_wire_parity::production_request_serializers_match_cpp_and_have_complete_coverage"
    mutate(
        "production-request",
        "tosctl/src/node-control/control-client/src/client_adnl.rs",
        replacement(
            "Ok(tos::rpc::engine::validator::GetTime {}.into_tl_object())",
            "Ok(tos::rpc::engine::validator::GetConfig {}.into_tl_object())",
        ),
        cargo("control-client", adapter_test),
        "CLI_REQUEST_BYTES",
    )
    mutate(
        "request-coverage",
        "tosctl/src/node-control/control-client/src/cli_wire_parity.rs",
        replacement(
            '    unit!(GetTimeRqRs, "engine.validator.getTime");',
            "    // Deliberately omit the time request coverage case.",
        ),
        cargo("control-client", adapter_test),
        "CLI_REQUEST_COVERAGE",
    )
    mutate(
        "safe-routing",
        "tosctl/src/adnl/src/overlay/mod.rs",
        replacement(
            'AdnlSendMethod::Safe => fail!("Safe overlay broadcast is unsupported"),',
            "AdnlSendMethod::Safe => BroadcastSimpleProtocol.send(ctx).await,",
        ),
        cargo(
            "adnl",
            "safe_overlay_broadcast_refuses_without_sending_and_fast_delivers",
            "test_overlay",
        ),
        "SAFE_BROADCAST_MUST_REFUSE",
    )

    native_mutations = [
        (
            "native-fields",
            "encode(*parsed.ok()).as_slice() == td::Slice(expected)",
            "true",
            "CPP_FIELD_ORACLE_SURVIVED",
        ),
        (
            "native-consumption",
            "td::BufferSlice(bytes), true",
            "td::BufferSlice(td::Slice(bytes.data(), std::min(bytes.size(), expected.size()))), true",
            "CPP_TRAILING_ORACLE_SURVIVED",
        ),
        (
            "native-completeness",
            "if (!names.empty() || count != expected.size())",
            "if (false)",
            "CPP_MISSING_ORACLE_SURVIVED",
        ),
        (
            "native-limit",
            "input.gcount() > 1024 * 1024",
            "false",
            "CPP_INPUT-LIMIT_ORACLE_SURVIVED",
        ),
    ]
    for name, old, new, marker in native_mutations:
        if args.control and name not in args.control:
            continue
        path = root / "test/tl-cli/fixtures.cpp"
        original = path.read_bytes()
        command = [
            "cmake",
            "--build",
            str(args.native_tool.resolve().parent),
            "--parallel",
            "2",
            "--target",
            "test-tl-cli-fixtures",
        ]
        if args.container:
            command = ["docker", "exec", "-w", str(root), args.container, *command]
        if run(command, name + "-build-before").returncode:
            raise RuntimeError(f"{name}: positive build failed")
        if run(
            native(["--verify", str(root / "test/tl-cli/fixtures.tsv")]), name + "-before"
        ).returncode:
            raise RuntimeError(f"{name}: positive fixture failed")
        try:
            path.write_text(replacement(old, new)(original.decode()))
            if run(command, name + "-build-red").returncode:
                raise RuntimeError(f"{name}: mutated build failed")
            red = run(
                [
                    "python3",
                    str(Path(__file__).resolve()),
                    "--checkout",
                    str(root),
                    "--target-dir",
                    str(args.target_dir.resolve()),
                    "--native-tool",
                    str(args.native_tool.resolve()),
                    "--output-dir",
                    str(out / name),
                    "--control",
                    "native-inputs",
                    *(["--container", args.container] if args.container else []),
                ],
                name + "-red",
            )
            if red.returncode == 0 or marker not in red.stdout:
                raise RuntimeError(f"{name}: native mutation did not reach {marker}")
        finally:
            path.write_bytes(original)
            if run(command, name + "-build-restored").returncode:
                raise RuntimeError(f"{name}: restored build failed")
        restored = run(
            native(["--verify", str(root / "test/tl-cli/fixtures.tsv")]), name + "-restored"
        )
        if restored.returncode:
            raise RuntimeError(f"{name}: restored verification failed")
        result.append(
            {
                "name": name,
                "red_exit": red.returncode,
                "restored_exit": restored.returncode,
                "marker": marker,
            }
        )
        (out / "result.json").write_text(json.dumps(result, indent=2) + "\n")
        print(f"TL_CONTROL_OK {name}", flush=True)

    if not args.control or "native-inputs" in args.control:
        original = (root / "test/tl-cli/fixtures.tsv").read_text()
        positive = run(
            native(["--verify", str(root / "test/tl-cli/fixtures.tsv")]), "native-positive"
        )
        if positive.returncode != 0 or "CPP_CLI_WIRE_OK" not in positive.stdout:
            raise RuntimeError("native positive control failed")
        lines = original.splitlines()
        name, payload = next(
            line.split("\t") for line in lines if line.startswith("engine.validator.addQuicAddr\t")
        )
        changed = bytearray.fromhex(payload)
        changed[4] ^= 1
        probes = {
            "field": (original.replace(name + "\t" + payload, name + "\t" + changed.hex()), 1),
            "trailing": (original.replace(name + "\t" + payload, name + "\t" + payload + "00"), 1),
            "missing": ("\n".join(lines[1:]) + "\n", 1),
            "duplicate": (original + lines[0] + "\n", 1),
            "input-limit": (original + " " * (1024 * 1024), 2),
        }
        for label, (text, code) in probes.items():
            path = out / f"native-{label}.tsv"
            path.write_text(text)
            done = run(native(["--verify", str(path)]), "native-" + label)
            if done.returncode != code:
                raise RuntimeError(
                    f"CPP_{label.upper()}_ORACLE_SURVIVED: expected {code}, got {done.returncode}"
                )
            result.append(
                {
                    "name": "native-" + label,
                    "red_exit": done.returncode,
                    "restored_exit": positive.returncode,
                }
            )
        (out / "result.json").write_text(json.dumps(result, indent=2) + "\n")
        print("TL_CONTROL_OK native-inputs", flush=True)


if __name__ == "__main__":
    main()
