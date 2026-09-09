#!/usr/bin/env python3
"""Exercise the production Fift approval predicate and generation guard."""
import argparse
import pathlib
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--create-state", type=pathlib.Path, required=True)
    parser.add_argument("--repo", type=pathlib.Path, required=True)
    parser.add_argument("--operators", type=pathlib.Path)
    parser.add_argument("--resources", type=pathlib.Path)
    parser.add_argument("--evidence", type=pathlib.Path)
    args = parser.parse_args()
    if args.evidence is None:
        args.evidence = pathlib.Path(tempfile.mkdtemp(prefix="uno-genesis-operator-evidence-")) / "run"
    args.evidence.mkdir(parents=True, exist_ok=False)
    operators = (args.operators or args.repo / "crypto/smartcont/uno-genesis-operators.fif").resolve()
    resources = (args.resources or args.repo / "crypto/smartcont/uno-genesis-config.fif").resolve()
    library = ":".join(map(str, (args.repo / "crypto/fift/lib",
                                args.create_state.resolve().parent / "smartcont",
                                args.repo / "crypto/smartcont")))
    assert args.create_state.is_file() and operators.is_file(), "980: missing executable or fixture"
    # Include the actual generator's prefix through its guard call. No keys,
    # BOCs, or addresses may be emitted before authorization succeeds.
    generator = (args.repo / "crypto/smartcont/gen-zerostate.fif").read_text()
    call = "globalid@ uno_development_coordinator uno_development_custody require-uno-genesis-operators"
    assert generator.count(call) == 1, "981: generator guard missing or duplicated"
    prefix = generator[:generator.index(call) + len(call)]
    assert "mkemptyShardState" not in prefix and "load-generate-keypair" not in prefix, "982: late guard"
    prefix = prefix.replace('"uno-genesis-operators.fif" include', f'"{operators}" include')
    cases = [
        ("mainnet-development", "1 0 0", False),
        ("mainnet-unapproved", "1 0x123456789abcdef 0xfedcba987654321", False),
        ("testnet-development", "-23901 0 0", True),
    ]
    with tempfile.TemporaryDirectory(prefix="uno-genesis-operators-") as directory:
        directory = pathlib.Path(directory)
        def run(name, script):
            source = directory / (name + ".fif")
            source.write_text(script)
            result = subprocess.run([str(args.create_state.resolve()), "-I", str(library), "-s", str(source)],
                                    cwd=directory, capture_output=True, timeout=30)
            (args.evidence / (name + ".stdout.log")).write_bytes(result.stdout)
            (args.evidence / (name + ".stderr.log")).write_bytes(result.stderr)
            return result
        for name, values, approved in cases:
            result = run(name, f'"{operators}" include\n{values} uno-genesis-operators-approved? . cr\n')
            assert result.returncode == 0, f"983: predicate did not execute: {name}"
            assert result.stdout.strip() == (b"-1" if approved else b"0"), f"984: wrong approval: {name}"
            result = run(name + "-guard", f'"{operators}" include\n{values} require-uno-genesis-operators\n991 . cr\n')
            assert (result.returncode == 0 and result.stdout.strip() == b"991") == approved, f"985: guard outcome: {name}"
            if not approved:
                assert result.returncode != 0 and b"991" not in result.stdout, f"986: unapproved pair continued: {name}"
        result = run("testnet-prefix", prefix.replace("1 setglobalid", "-23901 setglobalid") + "\n992 . cr\n")
        assert result.returncode == 0 and result.stdout.strip() == b"992", "988: prefix did not reach authorization"
        result = run("production-prefix", prefix + "\n992 . cr\n")
        assert result.returncode != 0 and b"992" not in result.stdout, "987: mainnet generator continued"
        result = run("resource-testnet", f'-23901 setglobalid\n"{resources}" include\n993 . cr\n')
        assert result.returncode == 0 and result.stdout.strip() == b"993", "989: resource fixture failed before guard"
        result = run("resource-mainnet", f'1 setglobalid\n"{resources}" include\n993 . cr\n')
        assert result.returncode != 0 and b"993" not in result.stdout, "990: unapproved mainnet resource continued"
    print("PASS: three approval cases, three guard cases, production and testnet prefixes")
    print(f"Evidence: {args.evidence}")


if __name__ == "__main__":
    main()
