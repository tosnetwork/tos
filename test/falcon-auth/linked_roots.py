"""Original linked native contexts, independently replayed by the Rust executor."""

# ruff: noqa: E402
import ctypes
import hashlib
import json
import subprocess
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "test/executor-parity"), str(ROOT / "test/auth-extensions")]
from cells import Cell, from_boc
from native import NOW, Emulator, config
from transaction_roots import MAX_INPUT_BYTES, compare, expected_row

# Measured from the unchanged default producers before migration. Names include
# capture ordinals, so dropping/reordering an identically labelled case fails.
POPULATIONS = {
    "two-hop": (1076, "6cb517095431c1a4a429434772847c2e222e71c56a95430f1f1eafad23cb9864", 688),
    "receipt": (164, "341f5d4e83f43ef63d5246c4fd2791ca5b7c1b312fb2872832c48efa2a457d0e", 8),
    "module-pq": (4, "7508efb2f7689913ba0e7afd5fa15f363e5e1daebb518aee514dd38a48f339c9", 0),
    "module-falcon": (4, "7508efb2f7689913ba0e7afd5fa15f363e5e1daebb518aee514dd38a48f339c9", 0),
}
EXCLUSIONS = {
    "two-hop": {
        "destination-limit injection": 8,
        "legacy Account helper assertion only": 36,
        "wrong-StateInit assertion only": 24,
        "external call": 12,
        "non-v16 call": 12,
        "bounce-return assertion only": 12,
    },
    "receipt": {},
    "module-pq": {},
    "module-falcon": {},
}
MODULE_CODES = {
    "module-pq": "570a064f8cd152c32f2c8a5694e1807c39cfb54efabb7e1147552a3c907cc239",
    "module-falcon": "6eddb777521f31be62601bf978d73e68c5048e3ba76d535c59390b6976bcd918",
}
ATTEMPTS = []


def configuration():
    fixture = from_boc((ROOT / "tosctl/src/executor/real_boc/default_config.boc").read_bytes())
    return Cell(bits=fixture.bits).ref(config(16))


def read(path):
    with path.open("rb") as stream:
        value = stream.read(MAX_INPUT_BYTES + 1)
    assert len(value) <= MAX_INPUT_BYTES, "linked artifact byte limit"
    return value


class CaptureEmulator(Emulator):
    """Use the same native constructor while retaining its actual send context."""

    def __init__(self, global_version=16, max_msg_cells=None, vm_log_verbosity=1):
        self.configuration = config(global_version, max_msg_cells)
        self.version, self.now = global_version, NOW
        self._initialize(self.configuration, vm_log_verbosity)
        self.lib.transaction_emulator_set_unixtime.restype = ctypes.c_bool
        self.last_capture = None

    def set_time(self, now):
        assert self.lib.transaction_emulator_set_unixtime(self.ptr, now)
        self.now = now

    def send(self, shard, message):
        assert len(ATTEMPTS) < 20_000, "linked send count limit"
        # Freeze original wire cells before native execution or caller mutation.
        original, inbound = shard.boc().hex(), message.boc().hex()
        result = super().send(shard, message)
        event = {"reason": "legacy Account helper assertion only", "captured": False}
        ATTEMPTS.append(event)
        self.last_capture = (
            original,
            inbound,
            self.lt,
            self.now,
            self.configuration.hash.hex(),
            {
                key: result[key]
                for key in ("success", "transaction", "shard_account")
                if key in result
            },
            event,
        )
        return result

    def exclude(self, reason):
        assert self.last_capture is not None and not self.last_capture[-1]["captured"]
        self.last_capture[-1]["reason"] = reason


@dataclass(frozen=True)
class Capture:
    name: str
    original: str
    message: str
    lt: int
    now: int
    native: dict
    legacy: str

    @classmethod
    def from_send(cls, name, prior, message, emulator, result, legacy):
        assert isinstance(emulator, CaptureEmulator) and emulator.version == 16
        original, inbound, lt, now, cfg, native, event = emulator.last_capture
        assert not event["captured"] and result["success"] is True
        assert original == prior.boc().hex() and inbound == message.boc().hex()
        assert cfg == configuration().refs[0].hash.hex(), "unexpected linked configuration"
        assert native["transaction"] == result["transaction"]
        assert native["shard_account"] == result["shard_account"]
        event.update(captured=True, reason="captured", name=name)
        return cls(name, original, inbound, lt, now, native, legacy)

    def old_input(self):
        account = from_boc(bytes.fromhex(self.original)).refs[0]
        return "\t".join(
            [self.name, str(self.now), str(self.lt), account.boc().hex(), self.message, "-"]
        )

    def root_input(self):
        return "\t".join(
            [
                self.name,
                str(self.now),
                str(self.lt),
                self.original,
                self.message,
                "0" * 64,
                "-",
                "-",
                "0",
            ]
        )


def export(records, driver, cfg, output, family, full):
    value = read(cfg)
    assert value == configuration().boc(), "unexpected root configuration"
    target = output / f"{family}-config.boc"
    if cfg.resolve() != target.resolve():
        target.write_bytes(value)
    count = compare(
        driver, cfg, [(row.root_input(), row.native) for row in records], output, family
    )
    receipt = {
        "family": family,
        "full": full,
        "rows": count,
        "source_commit": subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
        ).strip(),
        "configuration_sha256": hashlib.sha256(cfg.read_bytes()).hexdigest(),
        "exclusions": dict(Counter(e["reason"] for e in ATTEMPTS if not e["captured"])),
        "captured_attempts": sum(e["captured"] for e in ATTEMPTS),
    }
    assert receipt["captured_attempts"] == count
    (output / f"{family}-root-receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    validate(output, family, full=full)
    return count


def validate(directory, family, *, full=True):
    """Bind all ordered original contexts to native headers and raw output BOCs."""
    receipt = json.loads(read(directory / f"{family}-root-receipt.json"))
    assert receipt["family"] == family and receipt["full"] is full, "partial linked population"
    cfg = read(directory / f"{family}-config.boc")
    assert cfg == configuration().boc(), "unexpected linked v16 config"
    assert receipt["configuration_sha256"] == hashlib.sha256(cfg).hexdigest()
    inputs = read(directory / f"{family}-roots.tsv")
    lines = inputs.decode().splitlines()
    assert inputs.endswith(b"\n") and b"\r" not in inputs and lines.pop(0) == "#pq-tx-roots-v1"
    actual = read(directory / f"{family}-root-driver.stdout")
    claimed = read(directory / f"{family}-root-expected.tsv")
    assert actual.endswith(b"\n") and b"\r" not in actual
    got, claims = actual.decode().splitlines(), claimed.decode().splitlines()
    native = json.loads(read(directory / f"{family}-root-native.json"))
    assert 0 < len(lines) <= 10_000
    assert len(lines) == len(native) == len(got) == len(claims) == receipt["rows"], (
        "linked record count mismatch"
    )
    assert receipt["captured_attempts"] == len(lines)
    names = [line.split("\t")[0] for line in lines]
    if full:
        assert receipt["exclusions"] == EXCLUSIONS[family], "linked exclusions changed"
        count, digest, _ = POPULATIONS[family]
        assert len(lines) == count, "linked population count changed"
        assert hashlib.sha256("\n".join(names).encode()).hexdigest() == digest, (
            "linked population order changed"
        )
    previous, edges = {}, 0
    anchors = []
    for ordinal, (line, result, output, claim) in enumerate(
        zip(lines, native, got, claims, strict=True)
    ):
        fields = line.split("\t")
        assert len(fields) == 9 and fields[0].startswith(f"{ordinal}:")
        name, now, lt, original, message, seed, libraries, blocks, signatures = fields
        assert (seed, libraries, blocks, signatures) == ("0" * 64, "-", "-", "0")
        shard = from_boc(bytes.fromhex(original))
        s = shard.slice()
        predecessor, predecessor_lt = s.uint(256), s.uint(64)
        account = s.ref()
        s.end()
        if family in MODULE_CODES:
            assert predecessor == predecessor_lt == 0, "unexpected module predecessor"
            assert account.refs and account.refs[0].hash.hex() == MODULE_CODES[family], (
                "module profile code mismatch"
            )
        assert result.get("success") is True, "invalid linked native outcome"
        tx, after = from_boc(result["transaction"]), from_boc(result["shard_account"])
        t = tx.slice()
        assert t.uint(4) == 7
        address, transaction_lt = t.uint(256), t.uint(64)
        assert transaction_lt == int(lt) and int(lt) > 0
        assert t.uint(256) == predecessor and t.uint(64) == predecessor_lt, (
            "native predecessor mismatch",
            ordinal,
        )
        assert t.uint(32) == int(now) and int(now) > 0, ("native time mismatch", ordinal)
        a = account.slice()
        if a.uint(1):
            assert a.addr()[1] == address, "original Account identity mismatch"
        assert tx.refs[0].slice().maybe().hash == from_boc(bytes.fromhex(message)).hash
        update = tx.refs[1].slice()
        assert update.uint(8) == 0x72
        assert update.uint(256) == int.from_bytes(account.hash, "big"), (
            "native old Account mismatch",
            ordinal,
        )
        assert update.uint(256) == int.from_bytes(after.refs[0].hash, "big")
        update.end()
        end = after.slice()
        assert end.uint(256) == int.from_bytes(tx.hash, "big") and end.uint(64) == transaction_lt
        end.ref()
        end.end()
        if predecessor in previous:
            assert previous[predecessor] == (address, predecessor_lt, shard.hash), (
                "broken native predecessor"
            )
            edges += 1
        else:
            anchors.append({"ordinal": ordinal, "input_shard": shard.hash.hex()})
        previous[int.from_bytes(tx.hash, "big")] = (address, transaction_lt, after.hash)
        expected = "\t".join(expected_row(name, result))
        assert output == claim == expected, ("linked root mismatch", ordinal, name)
    if full:
        assert edges == POPULATIONS[family][2], "linked predecessor population changed"
    return inputs, cfg, actual, anchors


def compare_architectures(left, right, source):
    for directory in (left, right):
        assert read(directory / "commit.txt").decode().strip() == source, "stale linked source"
        assert json.loads(read(directory / "e2e.json"))["success"] is True, "linked producer failed"
        assert json.loads(read(directory / "two-hop-parity.json"))["success"] is True
        report = json.loads(read(directory / "receipts/receipt-e2e.json"))
        assert (
            report["success"] is True
            and report["cases"] == 64
            and report["transactions_compared"] == 164
        )
    for family, folder in (("two-hop", Path()), ("receipt", Path("receipts"))):
        signatures = []
        for directory in (left, right):
            path = directory / folder
            receipt = json.loads(read(path / f"{family}-root-receipt.json"))
            assert receipt["source_commit"] == source
            signatures.append(validate(path, family))
        assert signatures[0] == signatures[1], "linked architecture mismatch"
    print(
        "PASS: 1076 two-hop and164 receipt roots; authentic linked contexts on both architectures"
    )


def compare_module_architectures(left, right, family, source):
    assert family in MODULE_CODES, "unknown module family"
    signatures = []
    for directory in (left, right):
        assert read(directory.parent / "commit.txt").decode().strip() == source, (
            "stale module source"
        )
        receipt = json.loads(read(directory / f"{family}-root-receipt.json"))
        assert receipt["source_commit"] == source, "stale module receipt"
        report = json.loads(read(directory / "tx-parity.json"))
        assert report["success"] is True and report["transactions"] == 4, "module producer failed"
        assert report["source_commit"] == source, "stale module report"
        signatures.append(validate(directory, family))
    assert signatures[0] == signatures[1], "module architecture mismatch"
    print(f"PASS: {family} four complete roots on both architectures")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compare", nargs=2, type=Path, required=True)
    parser.add_argument("--module-family", choices=tuple(MODULE_CODES))
    args = parser.parse_args()
    source = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    if args.module_family:
        compare_module_architectures(*args.compare, args.module_family, source)
    else:
        compare_architectures(*args.compare, source)
