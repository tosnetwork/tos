#!/usr/bin/env python3
"""Compile remote-transport mutants and require isolated named failures."""
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
SOURCES = {
    "remote": ROOT / "validator/auth/remote-transport.cpp",
    "policy": ROOT / "validator/auth/http-transport-policy.h",
}

MUTATIONS = [
    (
        "certificate-principal",
        "certificate_principal_only",
        "remote",
        '  return handler(principal.value(), decoded.request);',
        '  return handler(Hash{}, decoded.request);',
    ),
    (
        "unmapped-certificate",
        "unmapped_certificate_refused",
        "remote",
        '  if (found == principals_.end())\n'
        '    return Error{"remote-principal-unmapped"};',
        '  if (found == principals_.end())\n'
        '    return principals_.begin()->second;',
    ),
    (
        "verified-chain",
        "verified_chain_required",
        "remote",
        '  if (!outcome.certificate_chain_verified)\n'
        '    return Error{"remote-certificate-unverified"};',
        '  if (false && !outcome.certificate_chain_verified)\n'
        '    return Error{"remote-certificate-unverified"};',
    ),
    (
        "client-certificate",
        "client_certificate_required",
        "remote",
        '  if (!outcome.client_certificate_present ||\n'
        '      outcome.leaf_certificate.empty())\n'
        '    return Error{"remote-client-certificate-required"};',
        '  if (false && (!outcome.client_certificate_present ||\n'
        '      outcome.leaf_certificate.empty()))\n'
        '    return Error{"remote-client-certificate-required"};',
    ),
    (
        "tls-version",
        "tls13_only",
        "remote",
        '  if (outcome.negotiated_version != remote_tls13_version)\n'
        '    return Error{"remote-tls-version"};',
        '  if (false && outcome.negotiated_version != remote_tls13_version)\n'
        '    return Error{"remote-tls-version"};',
    ),
    (
        "header-bytes",
        "header_byte_bound",
        "remote",
        '  if (decoded.header_bytes >\n'
        '      http_transport_max_header_bytes)\n'
        '    return Error{"http-header-bound"};',
        '  if (false && decoded.header_bytes >\n'
        '      http_transport_max_header_bytes)\n'
        '    return Error{"http-header-bound"};',
    ),
    (
        "header-count",
        "header_count_bound",
        "policy",
        '  if (fields.size() >= http_transport_max_headers)\n'
        '    return Error{"http-header"};',
        '  if (false && fields.size() >= http_transport_max_headers)\n'
        '    return Error{"http-header"};',
    ),
    (
        "body-size",
        "body_size_bound",
        "policy",
        '      request.body.size() > http_transport_max_body_bytes ||',
        '      false ||',
    ),
    (
        "absolute-deadline",
        "absolute_io_deadline",
        "policy",
        '  return start + http_transport_io_timeout;',
        '  return start + std::chrono::seconds(6);',
    ),
    (
        "duplicate-header",
        "duplicate_header_refused",
        "policy",
        '  if (fields.contains(name))\n'
        '    return Error{"http-duplicate-header"};',
        '  if (false && fields.contains(name))\n'
        '    return Error{"http-duplicate-header"};',
    ),
    (
        "transfer-encoding",
        "transfer_encoding_refused",
        "policy",
        '  return name == "transfer-encoding" || name == "content-encoding" ||\n'
        '         name == "upgrade" || name == "expect";',
        '  return name == "content-encoding" ||\n'
        '         name == "upgrade" || name == "expect";',
    ),
    (
        "compression",
        "compression_refused",
        "policy",
        '  return name == "transfer-encoding" || name == "content-encoding" ||\n'
        '         name == "upgrade" || name == "expect";',
        '  return name == "transfer-encoding" ||\n'
        '         name == "upgrade" || name == "expect";',
    ),
    (
        "redirect",
        "redirect_refused",
        "policy",
        '  return status >= 200 && status <= 599 &&\n'
        '         !(status >= 300 && status < 400);',
        '  return status >= 200 && status <= 599;',
    ),
    (
        "protocol-upgrade",
        "protocol_upgrade_refused",
        "policy",
        '  return name == "transfer-encoding" || name == "content-encoding" ||\n'
        '         name == "upgrade" || name == "expect";',
        '  return name == "transfer-encoding" || name == "content-encoding" ||\n'
        '         name == "expect";',
    ),
    (
        "framing-boundary",
        "framing_boundary_refuses",
        "remote",
        '  return Error{"http2-framing-unavailable"};',
        '  return true;',
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


def built(
    command: list[str], binary: Path, log: Path
) -> bool:
    binary.unlink(missing_ok=True)
    result = invoke(command, log)
    return (
        result.returncode == 0
        and binary.is_file()
        and binary.stat().st_size > 0
        and os.access(binary, os.X_OK)
    )


def passing(
    result: subprocess.CompletedProcess[str], expected: int
) -> bool:
    lines = result.stdout.splitlines()
    return (
        result.returncode == 0
        and result.stderr == ""
        and lines[-1:]
        == [f"SUMMARY cases={expected} passed={expected}"]
        and sum(line.startswith("CASE_PASS ") for line in lines)
        == expected
    )


def named_failure(
    result: subprocess.CompletedProcess[str], case: str
) -> bool:
    return (
        result.returncode == 1
        and result.stdout.splitlines() == [f"SETUP_OK {case}"]
        and result.stderr.splitlines()
        == [f"ASSERTION_FAILED {case}"]
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()

    build = args.build.resolve()
    folder = build / "test/validator-auth-implementation"
    mutant_root = folder / "remote-transport-mutant-root"
    copies = {
        "remote": folder / "mutated-remote-transport.cpp",
        "policy":
            mutant_root / "validator/auth/http-transport-policy.h",
    }
    binary = folder / "test-p0-remote-transport-mutant"
    args.out.mkdir(parents=True, exist_ok=True)

    originals = {
        key: source.read_text()
        for key, source in SOURCES.items()
    }
    production_digests = {
        key: hashlib.sha256(source.read_bytes()).hexdigest()
        for key, source in SOURCES.items()
    }

    for key, copy in copies.items():
        copy.parent.mkdir(parents=True, exist_ok=True)
        copy.write_text(originals[key])

    build_command = [
        "cmake", "--build", str(build), "--target",
        "test-p0-remote-transport-mutant", "-j2",
    ]
    if not built(
        build_command, binary, args.out / "baseline-build.log"
    ):
        raise RuntimeError(
            "baseline mutant target did not compile"
        )

    listed = invoke(
        [str(binary), "--list"], args.out / "cases.log"
    )
    cases = listed.stdout.splitlines()
    if listed.returncode != 0 or not cases:
        raise RuntimeError("case inventory failed")
    expected = len(cases)

    baseline = invoke([str(binary)], args.out / "baseline.log")
    if not passing(baseline, expected):
        raise RuntimeError("baseline suite failed")

    records: list[dict[str, object]] = []
    try:
        for guard, case, source_key, old, new in MUTATIONS:
            original = originals[source_key]
            if original.count(old) != 1:
                raise RuntimeError(
                    f"source anchor is not unique: {guard}"
                )

            changed = original.replace(old, new, 1)
            if changed == original:
                raise RuntimeError(
                    f"mutation did not reach source: {guard}"
                )

            for key, copy in copies.items():
                copy.write_text(originals[key])
            copies[source_key].write_text(changed)
            if copies[source_key].read_text() != changed:
                raise RuntimeError(
                    f"mutated source write mismatch: {guard}"
                )

            (args.out / f"{guard}.diff").write_text(
                "".join(
                    difflib.unified_diff(
                        original.splitlines(True),
                        changed.splitlines(True),
                        fromfile=str(SOURCES[source_key]),
                        tofile=str(copies[source_key]),
                    )
                )
            )

            compiled = built(
                build_command, binary,
                args.out / f"{guard}-build.log",
            )
            named = False
            isolated = False
            if compiled:
                target = invoke(
                    [str(binary), case],
                    args.out / f"{guard}-named.log",
                )
                named = named_failure(target, case)

                others = invoke(
                    [str(binary), f"--exclude={case}"],
                    args.out / f"{guard}-others.log",
                )
                isolated = passing(others, expected - 1)

            for key, copy in copies.items():
                copy.write_text(originals[key])

            restored_compile = built(
                build_command, binary,
                args.out / f"{guard}-restored-build.log",
            )
            restored = invoke(
                [str(binary)],
                args.out / f"{guard}-restored.log",
            )
            restored_ok = (
                restored_compile and passing(restored, expected)
            )
            production_unchanged = all(
                hashlib.sha256(source.read_bytes()).hexdigest()
                == production_digests[key]
                for key, source in SOURCES.items()
            )

            record = {
                "guard": guard,
                "case": case,
                "source": source_key,
                "edit_reached_source": True,
                "compiled": compiled,
                "named_assertion_failed": named,
                "other_cases_passed": isolated,
                "restored_baseline": restored_ok,
                "production_sources_unchanged":
                    production_unchanged,
            }
            records.append(record)
            (args.out / "mutations.json").write_text(
                json.dumps(records, indent=2) + "\n"
            )
            print(json.dumps(record), flush=True)

            if not (
                compiled and named and isolated
                and restored_ok and production_unchanged
            ):
                raise RuntimeError(
                    "mutation did not establish only its "
                    f"named case: {guard}"
                )
    finally:
        for key, copy in copies.items():
            copy.write_text(originals[key])

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
        print(f"HARNESS_FAILURE {error}", file=sys.stderr)
        sys.exit(2)
