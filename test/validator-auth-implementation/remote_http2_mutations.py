#!/usr/bin/env python3
"""Compile HTTP/2 framing mutants and require isolated named failures."""
from __future__ import annotations

import argparse
import difflib
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "validator/auth/remote-http2.cpp"

MUTATIONS = [
    (
        "response-end-headers",
        "single_stream_round_trip",
        "  const auto header_flags = static_cast<std::uint8_t>(\n"
        "      remote_http2_flag_end_headers | (response.body.empty() ? remote_http2_flag_end_stream : 0));",
        "  const auto header_flags = static_cast<std::uint8_t>(\n"
        "      response.body.empty() ? remote_http2_flag_end_stream : 0);",
    ),
    (
        "preface",
        "preface_required",
        "  if (!std::equal(preface.value().begin(), preface.value().end(),\n"
        "                  client_preface.begin(), client_preface.end()))\n"
        "    return Error{\"http2-preface\"};",
        "  if (false && !std::equal(preface.value().begin(), preface.value().end(),\n"
        "                  client_preface.begin(), client_preface.end()))\n"
        "    return Error{\"http2-preface\"};",
    ),
    (
        "frame-size",
        "frame_size_bound",
        "  if (length > remote_http2_frame_bytes)\n"
        "    return Error{\"http2-frame-size\"};",
        "  if (length > 0xffffff)\n"
        "    return Error{\"http2-frame-size\"};",
    ),
    (
        "end-headers",
        "continuation_spanning_refused",
        "  if ((headers.flags & remote_http2_flag_end_headers) == 0)\n"
        "    return Error{\"http2-continuation\"};",
        "  if (false && (headers.flags & remote_http2_flag_end_headers) == 0)\n"
        "    return Error{\"http2-continuation\"};",
    ),
    (
        "dynamic-table-setting",
        "dynamic_table_setting_refused",
        "    if (id == 1) {\n"
        "      if (value != 0)\n"
        "        return Error{\"http2-hpack-dynamic\"};",
        "    if (id == 1) {\n"
        "      if (false && value != 0)\n"
        "        return Error{\"http2-hpack-dynamic\"};",
    ),
    (
        "indexed-field",
        "indexed_field_refused",
        "    if ((representation & 0x80) != 0)\n"
        "      return Error{\"http2-hpack-indexed\"};",
        "    if ((representation & 0x80) != 0)\n"
        "      representation = 0x00;",
    ),
    (
        "incremental-indexing",
        "incremental_indexing_refused",
        "    if ((representation & 0xc0) == 0x40)\n"
        "      return Error{\"http2-hpack-dynamic\"};",
        "    if ((representation & 0xc0) == 0x40)\n"
        "      representation = 0x00;",
    ),
    (
        "huffman",
        "huffman_refused",
        "  if ((lead & 0x80) != 0)\n"
        "    return Error{\"http2-hpack-huffman\"};",
        "  if (false && (lead & 0x80) != 0)\n"
        "    return Error{\"http2-hpack-huffman\"};",
    ),
    (
        "multiplexing",
        "multiplexing_refused",
        "      if (frame.stream != headers.stream)\n"
        "        return Error{\"http2-multiplexing\"};",
        "      if (false && frame.stream != headers.stream)\n"
        "        return Error{\"http2-multiplexing\"};",
    ),
    (
        "trailers",
        "trailers_refused",
        "      if (frame.type == RemoteHttp2FrameType::headers)\n"
        "        return Error{\"http2-trailers\"};",
        "      if (frame.type == RemoteHttp2FrameType::headers)\n"
        "        frame.type = RemoteHttp2FrameType::data;",
    ),
    (
        "push",
        "push_refused",
        "  if (headers.type == RemoteHttp2FrameType::push_promise)\n"
        "    return Error{\"http2-push\"};",
        "  if (headers.type == RemoteHttp2FrameType::push_promise)\n"
        "    headers.type = RemoteHttp2FrameType::headers;",
    ),
    (
        "priority",
        "priority_refused",
        "  if (headers.type == RemoteHttp2FrameType::priority)\n"
        "    return Error{\"http2-priority\"};",
        "  if (headers.type == RemoteHttp2FrameType::priority)\n"
        "    headers.type = RemoteHttp2FrameType::headers;",
    ),
    (
        "window-update",
        "window_update_refused",
        "      if (frame.type == RemoteHttp2FrameType::window_update)\n"
        "        return Error{\"http2-flow-control\"};",
        "      if (frame.type == RemoteHttp2FrameType::window_update)\n"
        "        frame.type = RemoteHttp2FrameType::data;",
    ),
    (
        "fixed-window-setting",
        "fixed_initial_window_setting",
        "    } else if (id == 4) {\n"
        "      if (value != remote_http2_initial_window)\n"
        "        return Error{\"http2-flow-control\"};",
        "    } else if (id == 4) {\n"
        "      if (false && value != remote_http2_initial_window)\n"
        "        return Error{\"http2-flow-control\"};",
    ),
    (
        "content-length",
        "content_length_binding",
        "  if (declared && *declared != body.size())\n"
        "    return Error{\"http2-content-length\"};",
        "  if (false && declared && *declared != body.size())\n"
        "    return Error{\"http2-content-length\"};",
    ),
    (
        "response-window",
        "response_initial_window_bound",
        "      response.body.size() > remote_http2_initial_window ||",
        "      false ||",
    ),
]


def invoke(
    command: list[str], log: Path, timeout: int = 900
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    log.write_text(
        "$ " + " ".join(command)
        + f"\nexit_code={result.returncode}\n"
        + "--- stdout ---\n" + result.stdout
        + "--- stderr ---\n" + result.stderr
    )
    return result


def built(command: list[str], binary: Path, log: Path) -> bool:
    binary.unlink(missing_ok=True)
    result = invoke(command, log)
    return (
        result.returncode == 0
        and binary.is_file()
        and binary.stat().st_size > 0
        and os.access(binary, os.X_OK)
    )


def passing(result: subprocess.CompletedProcess[str], expected: int) -> bool:
    lines = result.stdout.splitlines()
    return (
        result.returncode == 0
        and result.stderr == ""
        and lines[-1:] == [f"SUMMARY cases={expected} passed={expected}"]
        and sum(line.startswith("CASE_PASS ") for line in lines) == expected
    )


def named_failure(
    result: subprocess.CompletedProcess[str], case: str
) -> bool:
    return (
        result.returncode == 1
        and result.stdout.splitlines() == [f"SETUP_OK {case}"]
        and result.stderr.splitlines() == [f"ASSERTION_FAILED {case}"]
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()

    build = args.build.resolve()
    folder = build / "validator/auth"
    source = folder / "mutated-remote-http2.cpp"
    binary = folder / "test-p0-remote-http2-mutant"
    args.out.mkdir(parents=True, exist_ok=True)

    original = SOURCE.read_text()
    production_digest = hashlib.sha256(SOURCE.read_bytes()).hexdigest()
    source.write_text(original)

    build_command = [
        "cmake", "--build", str(build), "--target",
        "test-p0-remote-http2-mutant", "-j2",
    ]
    if not built(build_command, binary, args.out / "baseline-build.log"):
        raise RuntimeError("baseline mutant target did not compile")

    listed = invoke([str(binary), "--list"], args.out / "cases.log")
    cases = listed.stdout.splitlines()
    if listed.returncode != 0 or not cases:
        raise RuntimeError("case inventory failed")
    expected = len(cases)

    baseline = invoke([str(binary)], args.out / "baseline.log")
    if not passing(baseline, expected):
        raise RuntimeError("baseline suite failed")

    records: list[dict[str, object]] = []
    try:
        for guard, case, old, new in MUTATIONS:
            if original.count(old) != 1:
                raise RuntimeError(f"source anchor is not unique: {guard}")
            changed = original.replace(old, new, 1)
            if changed == original:
                raise RuntimeError(f"mutation did not reach source: {guard}")
            source.write_text(changed)
            if source.read_text() != changed:
                raise RuntimeError(f"mutated source write mismatch: {guard}")

            (args.out / f"{guard}.diff").write_text(
                "".join(
                    difflib.unified_diff(
                        original.splitlines(True), changed.splitlines(True),
                        fromfile=str(SOURCE), tofile=str(source),
                    )
                )
            )

            compiled = built(
                build_command, binary, args.out / f"{guard}-build.log"
            )
            named = False
            isolated = False
            if compiled:
                target = invoke(
                    [str(binary), case], args.out / f"{guard}-named.log"
                )
                named = named_failure(target, case)
                others = invoke(
                    [str(binary), f"--exclude={case}"],
                    args.out / f"{guard}-others.log",
                )
                isolated = passing(others, expected - 1)

            source.write_text(original)
            restored_compile = built(
                build_command, binary,
                args.out / f"{guard}-restored-build.log",
            )
            restored = invoke([str(binary)], args.out / f"{guard}-restored.log")
            restored_ok = restored_compile and passing(restored, expected)
            production_unchanged = (
                hashlib.sha256(SOURCE.read_bytes()).hexdigest()
                == production_digest
            )

            record = {
                "guard": guard,
                "case": case,
                "edit_reached_source": True,
                "compiled": compiled,
                "named_assertion_failed": named,
                "other_cases_passed": isolated,
                "restored_source_matches": source.read_text() == original,
                "restored_baseline": restored_ok,
                "production_source_unchanged": production_unchanged,
            }
            records.append(record)
            (args.out / "mutations.json").write_text(
                json.dumps(records, indent=2) + "\n"
            )
            print(json.dumps(record), flush=True)

            if not (
                compiled and named and isolated and restored_ok
                and production_unchanged and source.read_text() == original
            ):
                raise RuntimeError(
                    f"mutation did not establish only its named case: {guard}"
                )
    finally:
        source.write_text(original)

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
        print(f"HARNESS_FAILURE {error}", file=sys.stderr)
        sys.exit(2)
