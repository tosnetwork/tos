"""Full original quantum module inputs and separate public-signature replay."""

# ruff: noqa: E402
import base64
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [
    str(ROOT / name)
    for name in (
        "test/auth-extensions",
        "test/falcon-auth",
        "test/wallet-quantum",
        "test/rescue-fee-gate",
    )
]
import native
from cells import Cell, read_dict
from fee_tx_parity import transcript
from linked_roots import Capture, CaptureEmulator
from root_cells import from_boc, prime
from test_identity import chain
from transaction_roots import compare, expected_row

DATA = Path(__file__).with_name("data")
HASHES = {
    "wallet-module-inputs.json": "d8838b2ec89acfc420c6b969fa9b6011efb6ecd31d3ffbbbd02b191cf3dc5b14",
    "wallet-module-signatures.json": "fe5dca514bccef7b96756094f313a6235f6bee58243931408f668e53db917ac2",
}
MAX_BYTES = 2 * 1024 * 1024
MODES = ("candidate", "diagnostic")


def read(path):
    assert path.is_file() and not path.is_symlink(), "invalid wallet-module file"
    assert path.stat().st_size <= MAX_BYTES, "wallet-module file size limit"
    with path.open("rb") as stream:
        value = stream.read(MAX_BYTES + 1)
    assert len(value) <= MAX_BYTES, "wallet-module file size limit"
    return value


def run_files():
    """Exact small artifact set consumed by the source-bound final comparator."""
    paths = {
        "native/results.json",
        "native/native-wallet-signatures.json",
        "parity.json",
        "recipient-control.json",
        "wallet-module-receipt.json",
    }
    for index in (0, 1):
        paths.update(
            f"configuration-{index}/" + name
            for name in (
                "config.boc",
                "scenarios.tsv",
                "native.tsv",
                "rust.tsv",
                "wallet-module-roots.tsv",
                "wallet-module-root-native.json",
                "wallet-module-root-expected.tsv",
                "wallet-module-root-driver.stdout",
            )
        )
    return paths


def module_files():
    return {prefix + name for prefix in ("", "recorded-replay/") for name in run_files()}


def lines(path):
    raw = read(path)
    assert raw.endswith(b"\n") and b"\r" not in raw, "wallet-module line endings"
    try:
        return raw.decode("utf-8").splitlines()
    except UnicodeError as error:
        raise AssertionError("wallet-module text encoding") from error


def json_value(value):
    assert isinstance(value, (bytes, str)) and len(value) <= MAX_BYTES, (
        "wallet-module JSON size limit"
    )
    depth, quoted, escaped = 0, False, False
    # Bound nesting before the JSON parser allocates nested containers. Some
    # Python versions parse deeply nested JSON without raising RecursionError.
    for byte in value.encode() if isinstance(value, str) else value:
        if quoted:
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                quoted = False
        elif byte == 34:
            quoted = True
        elif byte in (91, 123):
            depth += 1
            assert depth <= 32, "wallet-module JSON nesting limit"
        elif byte in (93, 125):
            depth -= 1
            assert depth >= 0, "invalid wallet-module JSON"

    def unique(pairs):
        result = {}
        for key, item in pairs:
            assert key not in result, "duplicate wallet-module JSON key"
            result[key] = item
        return result

    try:
        return json.loads(value, object_pairs_hook=unique)
    except (ValueError, RecursionError) as error:
        raise AssertionError("invalid wallet-module JSON") from error


def hex_hash(value):
    assert isinstance(value, str) and re.fullmatch("[0-9a-f]{64}", value), (
        "wallet-module hash encoding"
    )


def decode_bits(value):
    assert isinstance(value, dict) and set(value) == {"width", "hex"}
    width, encoded = value["width"], value["hex"]
    assert type(width) is int and 0 <= width <= 1023, "wallet-module bit width"
    assert isinstance(encoded, str) and len(encoded) == (width + 3) // 4
    assert re.fullmatch("[0-9a-f]*", encoded)
    number = int(encoded or "0", 16)
    assert number < (1 << width), "wallet-module bit padding"
    return f"{number:0{width}b}" if width else ""


def signature(value, key, *, encoded=False):
    size = 2420 if key == "primary" else 7856
    assert key in ("primary", "rescue"), "wallet-module signer key"
    assert isinstance(value, str), "wallet-module signature type"
    if encoded:
        assert len(value) == (size + 2) // 3 * 4, "wallet-module signature length"
        try:
            raw = base64.b64decode(value, validate=True)
        except ValueError as error:
            raise AssertionError("wallet-module signature encoding") from error
    else:
        assert len(value) == size * 2 and re.fullmatch("[0-9a-f]+", value), (
            "wallet-module signature length/encoding"
        )
        raw = bytes.fromhex(value)
    assert len(raw) == size, "wallet-module signature length"
    return raw


def fixtures():
    values = []
    for name, digest in HASHES.items():
        raw = read(DATA / name)
        assert hashlib.sha256(raw).hexdigest() == digest, "wallet-module fixture identity"
        values.append(json_value(raw))
    profiles, replay = values
    assert (
        set(profiles)
        == {"schema", "scenario_source", "configuration_source", "public_keys", "modes"}
        and profiles["schema"] == "wallet-module-inputs-v2"
    )
    assert (
        set(replay) == {"schema", "source", "modes"}
        and replay["schema"] == "wallet-module-signatures-v1"
    )
    assert (
        profiles["scenario_source"]
        == replay["source"]
        == "7da918d588e8e08c71d4ecf3fcfd89185fb62470"
    )
    assert isinstance(profiles["configuration_source"], str) and re.fullmatch(
        "[0-9a-f]{40}", profiles["configuration_source"]
    ), "wallet-module configuration provenance"
    assert set(profiles["public_keys"]) == {"primary", "rescue"}
    for key, size in (("primary", 1312), ("rescue", 32)):
        encoded = profiles["public_keys"][key]
        assert isinstance(encoded, str) and len(encoded) == (size + 2) // 3 * 4, (
            "wallet-module public key size"
        )
        assert len(base64.b64decode(encoded, validate=True)) == size, (
            "wallet-module public key size"
        )
    assert set(profiles["modes"]) == set(replay["modes"]) == set(MODES)
    for mode in MODES:
        profile = profiles["modes"][mode]
        assert set(profile) == {"now", "calls", "groups"}
        assert type(profile["now"]) is int and profile["now"] == (
            1789437600 if mode == "candidate" else 1780000000
        )
        assert isinstance(profile["calls"], list) and isinstance(replay["modes"][mode], list)
        assert len(profile["calls"]) == len(replay["modes"][mode]) == 7
        for request, fixed in zip(profile["calls"], replay["modes"][mode], strict=True):
            assert set(request) == {"key", "purpose", "digest"}, "wallet-module fixture call schema"
            assert request["key"] in ("primary", "rescue") and request["purpose"] == "auth"
            hex_hash(request["digest"])
            assert set(fixed) == {"key", "purpose", "digest", "signature"}, (
                "wallet-module fixture replay schema"
            )
            assert {key: fixed[key] for key in request} == request, (
                "wallet-module fixture replay identity"
            )
            signature(fixed["signature"], request["key"], encoded=True)
        assert isinstance(profile["groups"], list) and len(profile["groups"]) == 2
        uses = []
        for index, group in enumerate(profile["groups"]):
            assert set(group) == {"dictionary", "root", "rows"}
            hex_hash(group["dictionary"])
            hex_hash(group["root"])
            assert isinstance(group["rows"], list) and len(group["rows"]) == (
                15 if index == 0 else 4
            )
            for ordinal, row in enumerate(group["rows"]):
                assert set(row) == {
                    "address",
                    "code",
                    "data",
                    "account_bits_sha256",
                    "now",
                    "lt",
                    "exit",
                    "role",
                    "message",
                    "behavior",
                    "out_messages",
                    "authored_data",
                }
                for field in ("code", "data", "account_bits_sha256", "authored_data"):
                    hex_hash(row[field])
                assert row["now"] == profile["now"] and type(row["lt"]) is int and row["lt"] > 0
                assert row["role"] in {"module", "wallet", "recipient", "signature-mutant"}
                assert (row["role"] == "signature-mutant") is (index == 0 and ordinal == 14)
                assert (
                    type(row["exit"]) is int
                    and type(row["out_messages"]) is int
                    and 0 <= row["out_messages"] <= 1
                )
                assert set(row["behavior"]) == {"compute_success", "aborted", "action"}
                assert (
                    type(row["behavior"]["compute_success"])
                    is type(row["behavior"]["aborted"])
                    is bool
                )
                action = row["behavior"]["action"]
                assert action is None or (
                    set(action) == {"success", "code"}
                    and type(action["success"]) is bool
                    and type(action["code"]) is int
                )
                assert (
                    isinstance(row["address"], list)
                    and len(row["address"]) == 2
                    and type(row["address"][0]) is int
                    and row["address"][0] == 0
                )
                hex_hash(row["address"][1])
                item = row["message"]
                decode_bits(item["bits"])
                assert type(item["refs"]) is int and 0 <= item["refs"] <= 4, (
                    "wallet-module message reference count"
                )
                if item["kind"] == "signed":
                    assert set(item) == {
                        "bits",
                        "refs",
                        "kind",
                        "call",
                        "flip",
                        "body_bits",
                        "body_refs",
                        "request_hash",
                        "extra_hashes",
                    }
                    assert type(item["call"]) is int and 0 <= item["call"] < 7
                    assert (
                        type(item["flip"]) is bool
                        and type(item["body_refs"]) is int
                        and item["body_refs"] in (2, 3)
                    )
                    assert item["refs"] == 1 and type(item["refs"]) is int
                    decode_bits(item["body_bits"])
                    hex_hash(item["request_hash"])
                    assert len(item["extra_hashes"]) == item["body_refs"] - 2
                    for h in item["extra_hashes"]:
                        hex_hash(h)
                    uses.append(item["call"])
                else:
                    assert (
                        set(item) == {"bits", "refs", "kind", "prior"} and item["kind"] == "relay"
                    )
                    assert type(item["prior"]) is int and 0 <= item["prior"] < ordinal, (
                        "wallet-module relay order"
                    )
        assert sorted(uses) == [0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6]
    return profiles, replay


def calls(value, mode, *, recorded=False):
    profiles, fixed = fixtures()
    assert isinstance(value, list) and len(value) == 7, "wallet-module signature call count"
    result = []
    for index, (actual, expected) in enumerate(
        zip(value, profiles["modes"][mode]["calls"], strict=True)
    ):
        assert set(actual) == {"key", "purpose", "digest", "public_key", "signature"}
        assert {key: actual[key] for key in expected} == expected, (
            "wallet-module signature call identity"
        )
        public = base64.b64decode(profiles["public_keys"][expected["key"]], validate=True)
        assert actual["public_key"] == public.hex(), "wallet-module signature public key"
        raw = signature(actual["signature"], expected["key"])
        if recorded:
            assert raw == signature(
                fixed["modes"][mode][index]["signature"], expected["key"], encoded=True
            ), "wallet-module recorded signature mismatch"
        result.append(raw)
    return result


class SignatureReplay:
    def __init__(self, mode):
        self.mode, self.position = mode, 0
        self.profiles, fixed = fixtures()
        self.rows = fixed["modes"][mode]

    def invoke(self, signer, key, purpose, digest, expected_public):
        assert self.position < 7, "wallet-module replay exhausted"
        row = self.rows[self.position]
        assert {k: row[k] for k in ("key", "purpose", "digest")} == dict(
            key=key, purpose=purpose, digest=digest.hex()
        ), "wallet-module replay request drift"
        public = base64.b64decode(self.profiles["public_keys"][key], validate=True)
        assert expected_public == public, "wallet-module replay public key"
        raw = signature(row["signature"], key, encoded=True)
        signer.calls.append(
            dict(
                key=key,
                purpose=purpose,
                digest=digest.hex(),
                public_key=public.hex(),
                signature=raw.hex(),
            )
        )
        self.position += 1
        return raw

    def __enter__(self):
        import native_signer_fixture

        adapter = self
        self.patch = patch.object(
            native_signer_fixture.NativeSignerFixture,
            "invoke",
            lambda signer, *args: adapter.invoke(signer, *args),
        )
        self.patch.__enter__()
        return self

    def __exit__(self, kind, value, traceback):
        self.patch.__exit__(kind, value, traceback)
        if kind is None:
            assert self.position == 7, "wallet-module replay unused calls"


def recording_emulator(mode):
    profile = fixtures()[0]["modes"][mode]

    class Recording(CaptureEmulator):
        def __init__(self, global_version=16, max_msg_cells=None, vm_log_verbosity=1):
            self._setup(
                native.config(global_version, max_msg_cells),
                vm_log_verbosity,
                expected_version=global_version,
            )

        def _setup(self, configuration, vm_log_verbosity, expected_version=None):
            snapshot = from_boc(configuration.boc())
            assert snapshot.hash.hex() in {g["dictionary"] for g in profile["groups"]}, (
                "wallet-module capture configuration"
            )
            assert native.NOW == profile["now"], "wallet-module dynamic time"
            assert expected_version in (None, 16), "wallet-module capture version"
            super()._setup(snapshot, vm_log_verbosity, expected_version=16)
            assert self.version == 16, "wallet-module capture version"
            self.set_time(native.NOW)

    return Recording


def capture(name, prior, message, emulator, result):
    original, inbound, lt, now, cfg, oracle, event = emulator.last_capture
    assert result["success"] is True and oracle["success"] is True
    assert original == prior.boc().hex() and inbound == message.boc().hex()
    assert not event["captured"]
    event.update(captured=True, name=name, reason="captured")
    return Capture(name, original, inbound, lt, now, oracle, "")


def bind_message(message, rule, signatures, validated):
    assert message.bits == decode_bits(rule["bits"]) and len(message.refs) == rule["refs"], (
        "wallet-module message header"
    )
    if rule["kind"] == "relay":
        prior = rule["prior"]
        assert type(prior) is int and 0 <= prior < len(validated), "wallet-module relay order"
        outgoing = validated[prior]
        assert len(outgoing) == 1 and outgoing[0].hash == message.hash, (
            "wallet-module relay message"
        )
        return
    body = message.refs[0]
    assert body.bits == decode_bits(rule["body_bits"]) and len(body.refs) == rule["body_refs"], (
        "wallet-module message body"
    )
    assert body.refs[0].hash.hex() == rule["request_hash"], "wallet-module unsigned request"
    assert [ref.hash.hex() for ref in body.refs[2:]] == rule["extra_hashes"], (
        "wallet-module extra reference"
    )
    raw = signatures[rule["call"]]
    if rule["flip"]:
        raw = bytes([raw[0] ^ 1]) + raw[1:]
    rebuilt = Cell(bits=body.bits, refs=[body.refs[0], chain(raw), *body.refs[2:]])
    expected = prime(Cell(bits=message.bits, refs=[rebuilt]))
    assert expected.hash == message.hash, "wallet-module signature/message mismatch"


def export_run(directory, mode, groups, driver, recorded):
    profile = fixtures()[0]["modes"][mode]
    assert list(groups) == [g["dictionary"] for g in profile["groups"]], (
        "wallet-module group population"
    )
    for index, (_config, _legacy, _expected, records) in enumerate(groups.values()):
        folder = directory / f"configuration-{index}"
        compare(
            driver,
            folder / "config.boc",
            [(r.root_input(), r.native) for r in records],
            folder,
            "wallet-module",
        )
    receipt = dict(
        mode=mode,
        recorded=recorded,
        source=subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
    )
    (directory / "wallet-module-receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    validate_run(directory, mode, receipt["source"], recorded)


def validate_run(directory, mode, source, recorded):
    profile = fixtures()[0]["modes"][mode]
    receipt = json_value(read(directory / "wallet-module-receipt.json"))
    assert type(receipt.get("recorded")) is bool and receipt == dict(
        mode=mode, recorded=recorded, source=source
    ), "wallet-module receipt/source"
    signatures = calls(
        json_value(read(directory / "native/native-wallet-signatures.json")),
        mode,
        recorded=recorded,
    )
    report = json_value(read(directory / "parity.json"))
    assert len(report["groups"]) == 2
    deterministic, exact, native_details = [], [], []
    for group_index, group in enumerate(profile["groups"]):
        folder = directory / f"configuration-{group_index}"
        raw_config = read(folder / "config.boc")
        cfg = from_boc(raw_config)
        assert (
            len(cfg.bits) == 256
            and len(cfg.refs) == 1
            and cfg.hash.hex() == group["root"]
            and cfg.refs[0].hash.hex() == group["dictionary"]
        ), "wallet-module configuration identity"
        cp8 = read_dict(cfg.refs[0], 32)[8].refs[0].slice()
        assert cp8.uint(8) == 0xC4 and cp8.uint(32) == 16
        cp8.uint(64)
        cp8.end()
        inputs = lines(folder / "wallet-module-roots.tsv")
        assert inputs and inputs.pop(0) == "#pq-tx-roots-v1"
        oracles = json_value(read(folder / "wallet-module-root-native.json"))
        got = lines(folder / "wallet-module-root-driver.stdout")
        claimed = lines(folder / "wallet-module-root-expected.tsv")
        assert len(inputs) == len(oracles) == len(got) == len(claimed) == len(group["rows"]), (
            "wallet-module row population"
        )
        legacy, detailed, outgoing, group_details = [], [], [], []
        for ordinal, (line, oracle, output, claim, row) in enumerate(
            zip(inputs, oracles, got, claimed, group["rows"], strict=True)
        ):
            fields = line.split("\t")
            assert len(fields) == 9
            name, now, lt, raw, inbound, seed, libs, previous, ignore = fields
            assert name == f"{ordinal}:transaction-{ordinal:03d}", "wallet-module row order"
            assert now == str(row["now"]) and lt == str(row["lt"]), "wallet-module time/LT"
            assert (seed, libs, previous, ignore) == ("0" * 64, "-", "-", "0"), (
                "wallet-module context"
            )
            shard = from_boc(bytes.fromhex(raw))
            wrapper = shard.slice()
            assert wrapper.uint(256) == wrapper.uint(64) == 0, "wallet-module predecessor"
            account = wrapper.ref()
            wrapper.end()
            a = account.slice()
            assert a.uint(1) == 1
            assert a.addr() == (row["address"][0], int(row["address"][1], 16)), (
                "wallet-module Account address"
            )
            assert (
                hashlib.sha256(account.bits.encode()).hexdigest() == row["account_bits_sha256"]
            ), "wallet-module Account shape"
            assert len(account.refs) == 2 and account.refs[0].hash.hex() == row["code"], (
                "wallet-module code identity"
            )
            assert account.refs[1].hash.hex() == row["data"], "wallet-module input data"
            message = from_boc(bytes.fromhex(inbound))
            bind_message(message, row["message"], signatures, outgoing)
            assert (
                set(oracle) == {"success", "transaction", "shard_account"}
                and oracle.get("success") is True
                and "vm_exit_code" not in oracle
                and not oracle.get("external_not_accepted", False)
            ), "wallet-module native class"
            tx, after = from_boc(oracle["transaction"]), from_boc(oracle["shard_account"])
            t = tx.slice()
            assert t.uint(4) == 7 and t.uint(256) == int(row["address"][1], 16)
            assert (
                t.uint(64) == int(lt) and t.uint(256) == t.uint(64) == 0 and t.uint(32) == int(now)
            ), "wallet-module native header"
            assert tx.refs[0].slice().maybe().hash == message.hash, "wallet-module native input"
            update = tx.refs[1].slice()
            assert update.uint(8) == 0x72
            assert update.uint(256) == int.from_bytes(account.hash, "big") and update.uint(
                256
            ) == int.from_bytes(after.refs[0].hash, "big"), "wallet-module native update"
            update.end()
            end = after.slice()
            assert end.uint(256) == int.from_bytes(tx.hash, "big") and end.uint(64) == int(lt)
            end.ref()
            end.end()
            details = native.transaction_details(tx)
            group_details.append(details)
            assert (
                details["exit"] == row["exit"]
                and {k: details[k] for k in row["behavior"]} == row["behavior"]
            ), "wallet-module native behavior"
            data, balance = native.account_data(after)
            assert data.hash.hex() == row["authored_data"], "wallet-module authored state"
            emitted = native.outgoing(tx)
            assert len(emitted) == row["out_messages"], "wallet-module outgoing count"
            if row["role"] == "recipient":
                assert balance > 10**9
            if row["role"] in ("module", "signature-mutant") and row["exit"] == 0:
                assert balance >= 10**12
            expected = "\t".join(expected_row(name, oracle))
            assert output == claim == expected, "wallet-module root mismatch"
            # Only fully checked predecessors become relay sources.
            outgoing.append(emitted)
            plain = f"transaction-{ordinal:03d}"
            legacy.append("\t".join([plain, now, lt, account.boc().hex(), inbound, "-"]))
            result = dict(oracle, details=details)
            detailed.append(transcript(plain, result))
        assert lines(folder / "scenarios.tsv") == legacy, "wallet-module legacy input"
        assert lines(folder / "native.tsv") == lines(folder / "rust.tsv") == detailed, (
            "wallet-module legacy outcome"
        )
        entry = report["groups"][group_index]
        assert (
            entry["configuration"] == cfg.refs[0].hash.hex()
            and type(entry["transactions"]) is int
            and entry["transactions"] == len(inputs)
            and entry["differences"] == []
        ), "wallet-module legacy report"
        native_details.append(group_details)
        deterministic.append((raw_config, "\n".join(detailed)))
        exact.append(
            (
                raw_config,
                read(folder / "wallet-module-roots.tsv"),
                read(folder / "wallet-module-root-driver.stdout"),
                read(folder / "wallet-module-root-native.json"),
            )
        )
    results = json_value(read(directory / "native/results.json"))
    active, retired = native_details
    expected_cases = {
        "primary": dict(zip(("module", "wallet", "recipient"), active[:3], strict=True)),
        "invalid_primary_signature": active[3],
        "legacy_submit_53554231": active[4],
        "legacy_submit_53554232": active[5],
        "classical_field_refused": active[6],
        "rescue": dict(zip(("module", "wallet", "recipient"), active[7:10], strict=True)),
        "lock": dict(zip(("module", "wallet"), active[10:12], strict=True)),
        "signed_migration": dict(zip(("module", "wallet"), active[12:14], strict=True)),
        "global_retirement": retired[0],
        "global_retirement_rescue": dict(
            zip(("module", "wallet", "recipient"), retired[1:], strict=True)
        ),
    }
    assert results["cases"] == expected_cases, "wallet-module native report cases"
    assert results["module_code_hash"] == profile["groups"][0]["rows"][0]["code"], (
        "wallet-module native report module"
    )
    assert results["wallet_code_hash"] == profile["groups"][0]["rows"][1]["code"], (
        "wallet-module native report wallet"
    )
    generated_sha = hashlib.sha256(deterministic[0][0]).hexdigest() if mode == "candidate" else None
    assert results["chain_config_sha256"] == report["generated_config_sha256"] == generated_sha, (
        "wallet-module native report configuration"
    )
    assert results["chain_version"] == 16 and type(results["chain_version"]) is int
    assert results["network"] == ("42" * 32 if mode == "candidate" else f"{123:064x}")
    assert results["global_id"] == (1 if mode == "candidate" else 42)
    assert results["mutations"] == {
        "primary_signature": "guard deletion changed corrupted signature rejection 1808 to successful relay"
    }, "wallet-module signature control"
    assert (
        results["retirement_configuration"]
        == "Only ConfigParam 48 is replaced for the retirement control"
    )
    control = json_value(read(directory / "recipient-control.json"))
    assert control["exit"] != 0 and control["failure"] == "recipient state update missing", (
        "wallet-module recipient control"
    )
    return tuple(exact if recorded else deterministic)
