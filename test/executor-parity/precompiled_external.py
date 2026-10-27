"""Both executors must give external messages to precompiled contracts the same gas.

ConfigParam 45 lists contracts by code hash with a fixed gas usage. An external
message has no gas limit until the contract accepts it, only a credit, so the
listed usage is compared with what the account can pay for (gas_max), and the
VM that runs in place of a missing implementation gives an unaccepted external
the credit alone. Each case runs one transaction in the native emulator and in
the Rust executor (pq-tx-parity --details) at the current global version; the
outcomes must match each other and the expected outcome.

Usage: precompiled_external.py --driver <pq-tx-parity> --output <dir>
Needs EMULATOR_PATH like the other native harnesses.
"""

# ruff: noqa: E402
import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "test/auth-extensions")]
import native
from cells import Cell, from_boc, make_dict, read_dict
from transaction_roots import compare as compare_roots

VERSION = native.CURRENT_GLOBAL_VERSION
PROBE = (0, 0x4545)
SENDER = (0, 0x9999)
USAGE = 5000


def code(data):
    return Cell().raw(bytes(data))


ACCEPT = code([0xF8, 0x00])
NO_ACCEPT = code([])


def burn_then_accept(pow2):
    # UNTIL:<{ GASCONSUMED; 2^pow2 PUSHPOW2; GREATER }> ACCEPT
    return code([0x95, 0xF8, 0x07, 0x83, pow2 - 1, 0xBC, 0xE6, 0xF8, 0x00])


def gas_limit(configuration):
    prices = read_dict(configuration, 32)[21].refs[0].slice()
    tag = prices.uint(8)
    if tag == 0xD1:
        prices.uint(128)
        tag = prices.uint(8)
    assert tag == 0xDE
    prices.uint(64)  # gas_price
    return prices.uint(64)


def with_precompiled(configuration, contract, usage):
    entries = read_dict(configuration, 32)
    smc = Cell().uint(0xB0, 8).uint(usage, 64)  # precompiled_smc#b0
    listing = make_dict({int.from_bytes(contract.hash, "big"): smc}, 256)
    entries[45] = Cell().ref(Cell().uint(0xC0, 8).maybe(listing))
    return make_dict(entries, 32)


def with_gas_limit(configuration, limit):
    entries = read_dict(configuration, 32)
    prices = entries[21].refs[0].slice()
    updated = Cell()
    tag = prices.uint(8)
    if tag == 0xD1:
        updated.uint(tag, 8).uint(prices.uint(128), 128)
        tag = prices.uint(8)
    assert tag == 0xDE
    updated.uint(tag, 8).uint(prices.uint(64), 64)  # Preserve the gas price.
    prices.uint(64)  # Replace the ordinary gas limit.
    updated.uint(limit, 64).uint(prices.uint(5 * 64), 5 * 64)
    assert not prices.bits and not prices.refs
    entries[21] = Cell().ref(updated)
    return make_dict(entries, 32)


def native_row(name, result):
    if not result["success"]:
        return f"{name}\trejected"
    details = result["details"]
    _, balance = native.account_data(from_boc(result["shard_account"]))
    return f"{name}\t{str(details['compute_success']).lower()}\t{details['gas']}\t{balance}"


def rust_row(line):
    f = line.split("\t")
    if len(f) == 5:
        return f"{f[0]}\trejected"
    # name exit action messages balance data success gas aborted action_success
    return f"{f[0]}\t{f[6]}\t{f[7]}\t{f[4]}"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--driver", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=True)

    base = native.config(VERSION)
    limit = gas_limit(base)
    over = (limit - 1).bit_length()  # smallest power of two at or above the limit
    under = over - 2
    assert (1 << under) < limit // 2 and limit < (1 << over) < 2 * limit - limit // 8, limit

    external = native.external(PROBE, Cell())
    internal = native.internal(SENDER, PROBE, Cell())
    # name, code, listed usage, message, expected, optional gas limit
    cases = [
        ("ext-accept", ACCEPT, USAGE, external, f"true\t{USAGE}", None),
        ("ext-no-accept", NO_ACCEPT, USAGE, external, "rejected", None),
        ("ext-over-gas-max", ACCEPT, limit + 1, external, "rejected", None),
        ("ext-burn-under-credit", burn_then_accept(under), 0, external, "true\t0", None),
        ("ext-burn-over-credit", burn_then_accept(over), 0, external, "rejected", None),
        ("int-accept", ACCEPT, USAGE, internal, f"true\t{USAGE}", None),
    ]
    for boundary in [(1 << 32) - 1, 1 << 32, (1 << 32) + 1]:
        cases += [
            (f"ext-no-accept-credit-{boundary}", NO_ACCEPT, USAGE, external, "rejected", boundary),
            (f"ext-accept-credit-{boundary}", ACCEPT, USAGE, external, f"true\t{USAGE}", boundary),
        ]
    failures, report = [], {}
    fixture = from_boc((ROOT / "tosctl/src/executor/real_boc/default_config.boc").read_bytes())
    for name, contract, usage, message, expected, custom_limit in cases:
        configuration = with_precompiled(base, contract, usage)
        if custom_limit is not None:
            configuration = with_gas_limit(configuration, custom_limit)
        emulator = native.Emulator.from_config(configuration)
        try:
            shard = native.active_account(PROBE, contract, Cell())
            result = emulator.send(shard, message)
            lt = emulator.lt
        finally:
            emulator.close()
        mine = native_row(name, result)
        config_file = out / f"{name}-config.boc"
        config_file.write_bytes(Cell().uint(int(fixture.bits, 2), 256).ref(configuration).boc())
        scenario = "\t".join(
            [name, str(native.NOW), str(lt), shard.refs[0].boc().hex(), message.boc().hex(), "-"]
        )
        # The driver insists on a set of at least four scenarios; repeat this one.
        (out / f"{name}.tsv").write_text((scenario + "\n") * 4)
        command = [str(args.driver.resolve()), str(config_file), str(out / f"{name}.tsv")]
        command += [str(VERSION), "--details"]
        rust = subprocess.run(command, capture_output=True, text=True)
        if rust.returncode != 0:
            raise SystemExit(f"{name}: rust driver failed: {rust.stderr.strip()[-400:]}")
        theirs = rust_row(rust.stdout.splitlines()[0])
        # This caller supplies the original full wrapper. Its fresh emulator
        # keeps zero seed, no libraries/previous blocks, and signature checks.
        root_input = "\t".join(
            [
                name,
                str(native.NOW),
                str(lt),
                shard.boc().hex(),
                message.boc().hex(),
                "0" * 64,
                "-",
                "-",
                "0",
            ]
        )
        root_rows = compare_roots(args.driver, config_file, [(root_input, result)] * 4, out, name)
        report[name] = {"native": mine, "rust": theirs, "root_rows": root_rows}
        if mine != theirs:
            failures.append(f"{name}: executors differ\n  native {mine}\n  rust   {theirs}")
        outcome = mine.split("\t", 1)[1]
        if not outcome.startswith(expected):
            failures.append(f"{name}: expected {expected}, native gave {outcome}")
    summary = {"passed": not failures, "gas_limit": limit, "rows": report, "failures": failures}
    (out / "result.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary))
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
