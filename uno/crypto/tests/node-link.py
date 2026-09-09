"""Check actual ELF symbol retention, not reachability or execution permission."""
import argparse
import subprocess


ENTRIES = {
    "uno_crypto_verify_v2",
    "uno_crypto_system_encrypt_v1",
    "uno_crypto_system_verify_v1",
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expect", required=True, choices=("present", "absent"))
    parser.add_argument("binary")
    args = parser.parse_args()
    # A missing binary, tool, or symbol table is a failed measurement, never SKIP.
    result = subprocess.run(
        ["nm", "--defined-only", "--extern-only", args.binary],
        check=True, capture_output=True, text=True,
    )
    definitions = [line.split() for line in result.stdout.splitlines()]
    if not definitions:
        raise SystemExit("FAIL: no external definitions; the symbol instrument is silent")
    counts = {name: sum(bool(row) and row[-1] == name for row in definitions) for name in ENTRIES}
    expected = 1 if args.expect == "present" else 0
    if any(count != expected for count in counts.values()):
        raise SystemExit(f"FAIL: expected {expected} definition(s) per entry, measured {counts}")
    print(f"PASS: expected {args.expect}, measured {counts}; no execution or entropy claim")


if __name__ == "__main__":
    main()
