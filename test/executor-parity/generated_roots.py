"""Original generated-config fixtures: complete inputs, native roots and refusals."""

# ruff: noqa: E402
import hashlib
import json
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.extend(
    str(ROOT / path) for path in ("test/auth-extensions", "test/falcon-auth", "test/wallet-quantum")
)
import native
from cells import Cell, read_dict
from linked_roots import Capture, CaptureEmulator, read
from root_cells import from_boc
from transaction_roots import compare, expected_row

NOW = 1_789_437_600
CONFIG_ROOT = "65331f7022fe3173b4aebad27bef02f8027c25f8643a2265811293130d7bb23b"
DICTIONARY_ROOT = "d19d22b1bca12dc5a73a04cac7fa3cea7e6eb7bcd059af42803c18659c31cd37"
RELEASE = "generated-release-config"
POST = "generated-post-accept"
PROFILES = {
    RELEASE: (
        "9485982878052bb2b29a7ec48c0bda792f7bc912a8fa58237eb253b549a17f87",
        tuple(f"s{s}-{k}" for s in range(1, 4) for k in ("valid", "bitflip"))
        + ("s4-h20w4-valid", "s4-h20w4-bitflip", "dedicated-s2-valid", "dedicated-s2-bitflip"),
    ),
    POST: (
        "a741f24318735396aa89a1f11177b8129f60d846e85c9ead2e185c1dcbdbe945",
        (
            "unaccepted-small",
            "unaccepted-large",
            "accepted-small",
            "accepted-large",
            "accepted-exhaustion",
        ),
    ),
}
COUNTS = (1, 5000, 1, 5000, 0x7FFFFFFF)


def configuration(raw):
    root = from_boc(raw)
    assert len(root.bits) == 256 and len(root.refs) == 1, "generated ConfigParams shape"
    assert root.hash.hex() == CONFIG_ROOT, "unexpected generated configuration"
    assert root.refs[0].hash.hex() == DICTIONARY_ROOT, "unexpected generated dictionary"
    entries = read_dict(root.refs[0], 32)
    version = entries[8].refs[0].slice()
    assert version.uint(8) == 0xC4 and version.uint(32) == 16, "generated version mismatch"
    version.uint(64)
    version.end()
    policy = entries[48].refs[0].slice()
    assert policy.uint(8) == 0xA1 and policy.uint(256) == int("42" * 32, 16)
    assert policy.uint(64) == policy.uint(16) == 0 and policy.maybe() is None
    assert policy.uint(256) == int(
        "5e4380aedc95f8cb72de55f7506de0269b47c03ad1d1ed0e5184c332544262c0", 16
    )
    policy.end()
    prices = entries[21].refs[0].slice()
    tag = prices.uint(8)
    if tag == 0xD1:
        prices.uint(128)
        tag = prices.uint(8)
    assert tag in (0xDD, 0xDE)
    prices.uint(64)
    limit = prices.uint(64)
    if tag == 0xDE:
        prices.uint(64)
    assert prices.uint(64) == 20000, "generated gas credit mismatch"
    prices.uint(64 * 3)
    prices.end()
    return root, limit


def capture(name, prior, message, emulator, result):
    assert isinstance(emulator, CaptureEmulator) and emulator.version == 16
    original, inbound, lt, now, cfg, oracle, event = emulator.last_capture
    assert cfg == DICTIONARY_ROOT, "unexpected generated capture dictionary"
    assert original == prior.boc().hex() and inbound == message.boc().hex()
    assert not event["captured"]
    expected_row(name, oracle)  # Unknown failures and contradictory success fields fail.
    assert oracle == {key: result[key] for key in oracle}
    event.update(captured=True, reason="captured", name=name)
    return Capture(name, original, inbound, lt, now, oracle, "")


def input_profile(family, ordinal, fields):
    code_hash, names = PROFILES[family]
    name, now, lt, raw, message, seed, libraries, blocks, signatures = fields
    assert name == f"{ordinal}:{names[ordinal]}", "generated population order changed"
    assert int(now) == NOW and int(lt) == (ordinal + 2) * 1_000_000, "generated time/LT mismatch"
    assert (seed, libraries, blocks, signatures) == ("0" * 64, "-", "-", "0"), (
        "generated execution context mismatch"
    )
    shard = from_boc(bytes.fromhex(raw))
    wrapper = shard.slice()
    assert wrapper.uint(256) == wrapper.uint(64) == 0, "generated predecessor mismatch"
    account = wrapper.ref()
    wrapper.end()
    a = account.slice()
    assert a.uint(1) == 1
    address = a.addr()
    expected_address = (0, 1000 + ordinal) if family == RELEASE else (0, 7000)
    assert address == expected_address, "generated address/workchain mismatch"
    assert a.varuint(7) == a.varuint(7) == a.uint(3) == 0
    assert a.uint(32) == NOW and a.uint(1) == a.uint(64) == 0
    assert a.coins() == (100_000_000_000 if family == RELEASE else 10**15)
    assert a.maybe() is None and a.uint(1) == 1 and a.uint(2) == 0
    code, data = a.maybe(), a.maybe()
    assert a.maybe() is None
    a.end()
    assert code is not None and code.hash.hex() == code_hash, "generated probe code mismatch"
    assert data is not None
    if family == RELEASE:
        fixtures = {
            row[0]: row
            for row in (
                line.split("\t")
                for line in (ROOT / "test/rescue-fee-gate/suite-scenarios.tsv")
                .read_text()
                .splitlines()
            )
        }
        plain_name = names[ordinal].removeprefix("dedicated-")
        fixture = fixtures[plain_name]
        suite = 255 if ordinal >= 8 else int(fixture[4].split(":")[1])
        expected_data = Cell().uint(suite, 8)
        for operand in fixture[5:9]:
            expected_data.ref(from_boc(bytes.fromhex(operand)))
        with patch.object(native, "NOW", NOW):
            expected_message = native.internal(
                (0, 999), expected_address, Cell(), value=10_000_000_000
            )
    else:
        expected_data = Cell().uint(0, 32)
        expected_message = native.external(
            expected_address, Cell().uint(ordinal >= 2, 1).uint(COUNTS[ordinal], 32)
        )
    assert data.hash == expected_data.hash, "generated original data mismatch"
    inbound = from_boc(bytes.fromhex(message))
    assert inbound.hash == expected_message.hash, "generated original message mismatch"
    return shard, account, data, inbound, names[ordinal]


def native_behavior(family, ordinal, result, data, limit):
    if family == POST and ordinal < 2:
        assert result.get("success") is False and result.get("external_not_accepted") is True, (
            "generated external classification mismatch"
        )
        assert type(result.get("vm_exit_code")) is int and result["vm_exit_code"] == (
            0 if ordinal == 0 else -14
        ), "generated external rejection mismatch"
        assert "transaction" not in result and "shard_account" not in result
        return False
    assert result.get("success") is True, "generated native classification mismatch"
    assert "vm_exit_code" not in result and not result.get("external_not_accepted", False)
    assert {"transaction", "shard_account"} <= result.keys(), "generated native BOC missing"
    tx, after = from_boc(result["transaction"]), from_boc(result["shard_account"])
    details = native.transaction_details(tx)
    state, _ = native.account_data(after)
    assert not native.outgoing(tx), "generated unexpected outgoing message"
    if family == RELEASE:
        bad = ordinal % 2 == 1
        assert details["exit"] == (901 if bad else 0), "generated compute exit mismatch"
        assert details["compute_success"] is (not bad) and details["aborted"] is bad
        assert state.hash == (data if bad else Cell().uint(1, 1)).hash
        if not bad:
            assert details["action"] == {"success": True, "code": 0}
    elif ordinal == 4:
        assert details["exit"] == -14 and details["aborted"]
        assert state.hash == data.hash and details["gas"] == limit
    else:
        assert details["exit"] == 0 and not details["aborted"]
        assert details["compute_success"] and details["action"] == {"success": True, "code": 0}
        assert state.hash == Cell().uint(COUNTS[ordinal], 32).hash
        if ordinal == 3:
            assert details["gas"] > 20000
    return True


def bind_native(fields, result, account, inbound):
    tx, after = from_boc(result["transaction"]), from_boc(result["shard_account"])
    t = tx.slice()
    assert t.uint(4) == 7
    address = t.uint(256)
    a = account.slice()
    assert a.uint(1) == 1 and a.addr()[1] == address, "generated native address mismatch"
    assert t.uint(64) == int(fields[2]), "generated native LT mismatch"
    assert t.uint(256) == t.uint(64) == 0, "generated native predecessor mismatch"
    assert t.uint(32) == int(fields[1]), "generated native time mismatch"
    assert tx.refs[0].slice().maybe().hash == inbound.hash, "generated native message mismatch"
    update = tx.refs[1].slice()
    assert update.uint(8) == 0x72
    assert update.uint(256) == int.from_bytes(account.hash, "big"), (
        "generated native old Account mismatch"
    )
    assert update.uint(256) == int.from_bytes(after.refs[0].hash, "big"), (
        "generated native new Account mismatch"
    )
    update.end()
    end = after.slice()
    assert end.uint(256) == int.from_bytes(tx.hash, "big") and end.uint(64) == int(fields[2])
    end.ref()
    end.end()


def export(records, driver, config, output, family):
    configuration(read(config))
    compare(
        driver, config, [(record.root_input(), record.native) for record in records], output, family
    )
    receipt = {
        "family": family,
        "source": subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
        ).strip(),
        "configuration_sha256": hashlib.sha256(read(config)).hexdigest(),
        "rows": len(records),
    }
    (output / f"{family}-receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    validate(output, family, receipt["source"])


def read_lines(path):
    data = read(path)
    assert data.endswith(b"\n") and b"\r" not in data, "incomplete generated records"
    return data.decode().splitlines()


def validate(directory, family, source):
    receipt = json.loads(read(directory / f"{family}-receipt.json"))
    assert receipt["source"] == source, "stale generated source"
    assert receipt["family"] == family
    raw_config = read(directory / "config.boc")
    config_root, limit = configuration(raw_config)
    assert receipt["configuration_sha256"] == hashlib.sha256(raw_config).hexdigest()
    root_input = read(directory / f"{family}-roots.tsv")
    assert root_input.endswith(b"\n") and b"\r" not in root_input
    lines = root_input.decode().splitlines()
    assert lines.pop(0) == "#pq-tx-roots-v1"
    outputs = read_lines(directory / f"{family}-root-driver.stdout")
    claims = read_lines(directory / f"{family}-root-expected.tsv")
    oracles = json.loads(read(directory / f"{family}-root-native.json"))
    names = PROFILES[family][1]
    assert (
        len(lines) == len(outputs) == len(claims) == len(oracles) == len(names) == receipt["rows"]
    ), "generated record count mismatch"
    legacy_input, legacy_native = [], []
    for ordinal, (line, result, output, claimed) in enumerate(
        zip(lines, oracles, outputs, claims, strict=True)
    ):
        fields = line.split("\t")
        assert len(fields) == 9
        shard, account, data, inbound, name = input_profile(family, ordinal, fields)
        if native_behavior(family, ordinal, result, data, limit):
            bind_native(fields, result, account, inbound)
        expected = "\t".join(expected_row(fields[0], result))
        assert output == claimed == expected, "generated root mismatch"
        legacy_input.append(
            "\t".join([name, fields[1], fields[2], account.boc().hex(), fields[4], "-"])
        )
        # Read the original detailed transcript from independent native BOCs.
        from fee_tx_parity import transcript

        detailed = dict(result)
        if result["success"]:
            detailed["details"] = native.transaction_details(from_boc(result["transaction"]))
        legacy_native.append(transcript(name, detailed))
    assert read_lines(directory / "scenarios.tsv") == legacy_input, (
        "generated legacy input mismatch"
    )
    assert read_lines(directory / "native.tsv") == legacy_native, "generated legacy native mismatch"
    assert read_lines(directory / "rust.tsv") == legacy_native, "generated legacy Rust mismatch"
    report = json.loads(read(directory / "result.json"))
    assert (
        report["passed"] is True
        and report["config_sha256"] == hashlib.sha256(raw_config).hexdigest()
    ), "generated producer report mismatch"
    if family == RELEASE:
        assert (
            report["config_root"] == config_root.refs[0].hash.hex()
            and report["version"] == 16
            and report["namespace"] == "42" * 32
        )
        assert [row["name"] for row in report["cases"]] == list(names)
        for index, row in enumerate(report["cases"]):
            assert row["exit"] == (901 if index % 2 else 0) and row["state_changed"] is (
                index % 2 == 0
            )
            assert (
                row["gas"]
                == native.transaction_details(from_boc(oracles[index]["transaction"]))["gas"]
            )
    else:
        assert [row["name"] for row in report["measurements"]] == list(names)
        for index, row in enumerate(report["measurements"]):
            assert row["transaction_accepted"] is (index >= 2)
            expected_exit = (
                oracles[index]["vm_exit_code"]
                if index < 2
                else native.transaction_details(from_boc(oracles[index]["transaction"]))["exit"]
            )
            assert row["exit"] == expected_exit
            if index >= 2:
                assert (
                    row["gas"]
                    == native.transaction_details(from_boc(oracles[index]["transaction"]))["gas"]
                )
    return root_input, raw_config, "\n".join(outputs)
