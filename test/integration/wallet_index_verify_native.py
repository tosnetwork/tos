#!/usr/bin/env python3
"""Verify untrusted wallet-index snapshots on native node stores, honest and tampered.

Input is the stopped image node_sync_init_block.py leaves: validators holding
the chain from Genesis (the full source) and an observer that joined at a
persistent init block (the joined source). Every index, snapshot and receipt
goes below a new --root; both sources are inventoried before and after and
must be unchanged.

Scenarios (each its own receipt, <root>/<scenario>/receipt.json):

- reference: full replay of the full source to its tip.
- path-b: a donor index at checkpoint C on the full source, exported, imported
  untrusted into the joined source, verified until Full; its canonical digest
  equals that of a full replay of the full source to exactly the import's
  head, over the import's whole stored window.
- path-a: an empty index on the joined source, built from the window's blocks,
  Full, the same digest.
- red controls: the path-b snapshot edited as each names, each refused with
  its named reason and never served (never /readyz 200, exit 2).

A scenario whose capability is not in the binaries under test fails naming the
stage that provides it; nothing is skipped silently. The final line
NATIVE_WALLET_INDEX_VERIFY_OK is printed only when every requested scenario
passed.
"""

import argparse
import hashlib
import http.client
import importlib.util
import json
import re
import socket
import subprocess
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
# A decoded JSON object: /readyz bodies and receipts.
JsonObject = dict[str, object]


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


RECORDS = load("wallet_index_snapshot_records", HERE / "wallet_index_snapshot_records.py")
SNAPSHOT_RUNNER = load("wallet_index_snapshot_native", HERE / "wallet_index_snapshot_native.py")

# How long one service run may take before it is a failure.
SERVICE_SECONDS = 900
# The checkpoint is this many masterchain blocks above the joined source's
# init block, so the joined source holds it and the blocks after it.
CHECKPOINT_ABOVE_INIT = 2


class Unavailable(RuntimeError):
    """A capability the binaries under test do not have yet."""


@dataclass
class Image:
    full: Path
    joined: Path
    init_seqno: int
    fixtures: dict[str, Any] = field(default_factory=dict)


def discover_image(init_root: Path) -> Image:
    """The full and the joined source of a stopped init-block image."""
    receipt = json.loads((init_root / "init-block-receipt.json").read_text())
    if receipt.get("result") not in ("NATIVE_INIT_BLOCK_JOIN_OK", "NATIVE_WALLET_INDEX_IMAGE_OK"):
        raise RuntimeError("the init-block image did not complete")
    network = init_root / "network"
    joined = network / receipt["source"]
    excluded = {receipt["source"], receipt["target"]}
    stores = sorted(
        node
        for node in network.iterdir()
        if node.name not in excluded
        and all((node / child).is_dir() for child in ("state", "celldb", "archive"))
    )
    if not stores:
        raise RuntimeError("the init-block image has no full source")
    fixtures_file = init_root / "wallet-index-fixtures.json"
    fixtures = json.loads(fixtures_file.read_text()) if fixtures_file.exists() else {}
    if fixtures and fixtures.get("result") != "NATIVE_WALLET_INDEX_FIXTURES_OK":
        raise RuntimeError("the wallet lifecycle fixtures did not complete")
    return Image(stores[0], joined, int(receipt["init_block"]["seqno"]), fixtures)


@dataclass
class ServiceRun:
    """One run of tos-wallet-index, observed through /readyz until `until`."""

    exit_code: int | None = None
    # Whether `until` held before the service exited or was stopped.
    reached: bool = False
    readyz: JsonObject = field(default_factory=dict)
    ever_ready: bool = False
    phases: list[tuple[float, object, object]] = field(default_factory=list)
    seconds: float = 0.0
    peak_rss_kib: int | None = None
    log: str = ""


def peak_rss_kib(pid: int) -> int | None:
    try:
        for line in Path(f"/proc/{pid}/status").read_text().splitlines():
            if line.startswith("VmHWM:"):
                return int(line.split()[1])
    except OSError:
        return None
    return None


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def readyz(port: int) -> tuple[int, JsonObject] | None:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
    try:
        connection.request("GET", "/readyz")
        response = connection.getresponse()
        return response.status, json.loads(response.read(1 << 20))
    except (OSError, http.client.HTTPException, ValueError):
        return None
    finally:
        connection.close()


def run_service(
    binary: Path,
    source: Path,
    data: Path,
    flags: list[str],
    until: Callable[[int, JsonObject], bool],
    log: Path,
) -> ServiceRun:
    """Run the service until `until(status, readyz)` holds or it exits."""
    port = free_port()
    command = [
        str(binary),
        "--source-db",
        str(source),
        "--data-dir",
        str(data),
        "--listen",
        f"127.0.0.1:{port}",
        *flags,
    ]
    run = ServiceRun()
    started = time.monotonic()
    with log.open("wb") as stream:
        process = subprocess.Popen(command, stdout=stream, stderr=subprocess.STDOUT)
        try:
            last_phase: tuple[object, object] | None = None
            while time.monotonic() - started < SERVICE_SECONDS:
                run.peak_rss_kib = peak_rss_kib(process.pid) or run.peak_rss_kib
                if process.poll() is not None:
                    break
                answer = readyz(port)
                if answer is not None:
                    status, body = answer
                    run.readyz = body
                    run.ever_ready = run.ever_ready or status == 200
                    phase = (body.get("verification"), body.get("verification_phase"))
                    if phase != last_phase:
                        run.phases.append(
                            (round(time.monotonic() - started, 3), phase[0], phase[1])
                        )
                        last_phase = phase
                    if until(status, body):
                        run.reached = True
                        break
                time.sleep(0.5)
            else:
                raise TimeoutError(f"service never reached the expected state; see {log}")
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=30)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
    run.exit_code = process.returncode
    run.seconds = round(time.monotonic() - started, 3)
    run.log = log.read_text(errors="replace")
    return run


def tool(build: Path, *args: str, receipt: Path) -> str:
    return SNAPSHOT_RUNNER.command(
        [str(build / "services/tos-wallet-index-snapshot"), *args], receipt
    )


def require_reached(run: ServiceRun, label: str) -> None:
    """A positive scenario's service reached its state and stopped cleanly."""
    if not run.reached:
        raise RuntimeError(f"{label}: the service exited {run.exit_code} before the expected state")
    if run.exit_code != 0:
        raise RuntimeError(f"{label}: the service did not stop cleanly (exit {run.exit_code})")


@dataclass
class CanonicalDump:
    sha256: str
    head: int
    window_base: int


def canonical_digest(
    build: Path, index: Path, head: int, base_from: Path | None, receipt: Path
) -> CanonicalDump:
    """The canonical digest of a stopped index at checkpoint `head` (stage 4d's dump).

    The window is the index's own stored base (which replay may have moved
    past the base its verification recorded), or, from `base_from`, another
    stopped index's base at the same checkpoint, which may only narrow it. The
    dump prints the head and base it used.
    """
    dump = build / "services/tos-wallet-index-dump"
    probe = subprocess.run([str(dump), "--help"], capture_output=True, text=True, timeout=30)
    if "--canonical" not in probe.stdout + probe.stderr:
        raise Unavailable("the canonical dump (stage 4d) is not in this build")
    command = [str(dump), "--canonical", "--index-dir", str(index), "--head", str(head)]
    if base_from is not None:
        command += ["--window-base-from", str(base_from)]
    text = SNAPSHOT_RUNNER.command(command, receipt)
    fields = dict(re.findall(r"(?m)^(sha256|head|window_base)=(\S+)$", text))
    if not re.fullmatch("[0-9a-f]{64}", fields.get("sha256", "")):
        raise RuntimeError("the canonical dump printed no digest")
    result = CanonicalDump(
        fields["sha256"], int(fields.get("head", -1)), int(fields.get("window_base", -1))
    )
    if result.head != head:
        raise RuntimeError("the canonical dump used another window than the one asked for")
    return result


def common_window_digests(
    build: Path, imported: Path, reference: Path, head: int, out: Path
) -> tuple[CanonicalDump, CanonicalDump]:
    """Both indexes' digests at checkpoint `head` over the import's whole
    stored window. The import's window is never narrowed: a reference that
    does not cover it (a higher base) fails the comparison."""
    own = canonical_digest(build, imported, head, None, out / "dump.log")
    covered = canonical_digest(build, reference, head, None, out / "reference-own-dump.log")
    if covered.window_base > own.window_base:
        raise RuntimeError(
            f"the reference's window (base {covered.window_base}) does not cover the import's "
            f"(base {own.window_base})"
        )
    other = canonical_digest(build, reference, head, imported, out / "reference-dump.log")
    if own.window_base != other.window_base:
        raise RuntimeError("the canonical dumps used different windows")
    return own, other


@dataclass
class Context:
    build: Path
    root: Path
    image: Image
    checkpoint: int
    service: Path
    # The reference index (full replay of the full source) and its tip.
    reference_index: Path | None = None
    reference_tip: int | None = None
    donor_snapshot: Path | None = None
    # Full replays of the full source to exactly a given head.
    references_at: dict[int, Path] = field(default_factory=dict)


def until_full(status: int, body: JsonObject) -> bool:
    return status == 200 and body.get("verification") == "full" and body.get("caught_up") is True


def until_caught_up(status: int, body: JsonObject) -> bool:
    return status == 200 and body.get("caught_up") is True and body.get("settled") is True


def scenario_reference(context: Context, out: Path) -> JsonObject:
    data = out / "data"
    run = run_service(
        context.service, context.image.full, data, [], until_caught_up, out / "service.log"
    )
    require_reached(run, "reference")
    tip = run.readyz.get("masterchain_seqno")
    if not isinstance(tip, int):
        raise RuntimeError("the reference reported no masterchain seqno")
    context.reference_index = data / "index"
    context.reference_tip = tip
    return {"run": run.__dict__ | {"log": None}, "tip": tip}


def reference_at(context: Context, head: int) -> Path:
    """A full replay of the full source to exactly `head`, made once per head:
    ownership at another head cannot be compared by filtering history."""
    if head in context.references_at:
        return context.references_at[head]
    out = context.root / f"reference-at-{head}"
    out.mkdir()
    run = run_service(
        context.service,
        context.image.full,
        out / "data",
        ["--replay-ceiling", str(head)],
        lambda status, body: body.get("masterchain_seqno") == head and body.get("settled") is True,
        out / "service.log",
    )
    require_reached(run, f"reference at {head}")
    context.references_at[head] = out / "data/index"
    return context.references_at[head]


def donor_snapshot(context: Context) -> Path:
    """The honest snapshot at checkpoint C, made once from the full source."""
    if context.donor_snapshot is not None:
        return context.donor_snapshot
    out = context.root / "donor"
    out.mkdir()
    run = run_service(
        context.service,
        context.image.full,
        out / "data",
        ["--replay-ceiling", str(context.checkpoint)],
        lambda status, body: (
            body.get("masterchain_seqno") == context.checkpoint and body.get("settled") is True
        ),
        out / "service.log",
    )
    require_reached(run, "donor")
    snapshot = out / "checkpoint.snapshot"
    tool(
        context.build,
        "--action",
        "create",
        "--index-dir",
        str(out / "data/index"),
        "--snapshot",
        str(snapshot),
        receipt=out / "create.log",
    )
    context.donor_snapshot = snapshot
    return snapshot


def import_edited(
    context: Context,
    out: Path,
    edit: Callable[[object], None] | None,
    original: Path | None = None,
) -> Path:
    """Import the donor snapshot, edited by `edit`, untrusted into a new index."""
    snapshot = RECORDS.parse((original or donor_snapshot(context)).read_bytes())
    if edit is not None:
        edit(snapshot)
    file = out / "edited.snapshot"
    file.write_bytes(RECORDS.encode(snapshot))
    data = out / "data"
    data.mkdir()
    tool(
        context.build,
        "--action",
        "import-untrusted",
        "--snapshot",
        str(file),
        "--index-dir",
        str(data / "index"),
        receipt=out / "import.log",
    )
    return data


def scenario_path_b(context: Context, out: Path) -> JsonObject:
    data = import_edited(context, out, None)
    run = run_service(
        context.service, context.image.joined, data, [], until_full, out / "service.log"
    )
    require_reached(run, "path-b")
    if context.reference_index is None or context.reference_tip is None:
        raise RuntimeError("path-b needs the reference scenario first")
    head = run.readyz.get("masterchain_seqno")
    if not isinstance(head, int):
        raise RuntimeError("the verified import reported no head")
    if context.reference_tip < head:
        raise RuntimeError("the reference stops before the verified import's head")
    # At the import's head, against a reference replayed to exactly that head,
    # over the import's whole stored window.
    own, other = common_window_digests(
        context.build, data / "index", reference_at(context, head), head, out
    )
    if own.sha256 != other.sha256:
        raise AssertionError("the verified import differs from the reference over its window")
    return {
        "run": run.__dict__ | {"log": None},
        "head": head,
        "window_base": own.window_base,
        "digests": {"import": own.sha256, "reference": other.sha256},
    }


def scenario_path_a(context: Context, out: Path) -> JsonObject:
    data = out / "data"
    run = run_service(
        context.service, context.image.joined, data, [], until_full, out / "service.log"
    )
    require_reached(run, "path-a")
    head = run.readyz.get("masterchain_seqno")
    if not isinstance(head, int):
        raise RuntimeError("the bulk-built index reported no head")
    own, other = common_window_digests(
        context.build, data / "index", reference_at(context, head), head, out
    )
    if own.sha256 != other.sha256:
        raise AssertionError("the bulk-built index differs from the full replay over its window")
    return {
        "run": run.__dict__ | {"log": None},
        "head": head,
        "window_base": own.window_base,
        "digests": {"built": own.sha256, "reference": other.sha256},
    }


def first_account_with(snapshot, count: int) -> bytes:
    """An account with at least `count` history rows in the snapshot."""
    counts: dict[bytes, int] = {}
    for account, _, _ in snapshot.events():
        counts[account] = counts.get(account, 0) + 1
    for account, rows in sorted(counts.items()):
        if rows >= count:
            return account
    raise RuntimeError(f"the snapshot has no account with {count} history rows")


def edit_tampered(snapshot, account: bytes | None = None) -> None:
    account, lt, value = snapshot.events(account or first_account_with(snapshot, 1))[0]
    snapshot.put(RECORDS.event_key(account, lt), RECORDS.tamper_value(value))


def edit_omitted(snapshot, account: bytes | None = None) -> None:
    rows = snapshot.events(account or first_account_with(snapshot, 3))
    if len(rows) < 3:
        raise RuntimeError("omitted control needs three real history rows")
    account, lt, _ = rows[1]
    snapshot.delete(RECORDS.event_key(account, lt))


def edit_truncated(snapshot, account: bytes | None = None) -> None:
    rows = snapshot.events(account or first_account_with(snapshot, 2))
    if len(rows) < 2:
        raise RuntimeError("truncated control needs two real history rows")
    account, lt, _ = rows[-1]
    snapshot.delete(RECORDS.event_key(account, lt))


def edit_wrong_checkpoint(snapshot) -> None:
    point = RECORDS.checkpoint(snapshot)
    RECORDS.set_checkpoint(
        snapshot, RECORDS.Checkpoint(point.anchor, RECORDS.flip_root_hash(point.committed))
    )


def edit_wrong_anchor(snapshot) -> None:
    point = RECORDS.checkpoint(snapshot)
    RECORDS.set_checkpoint(
        snapshot, RECORDS.Checkpoint(RECORDS.flip_root_hash(point.anchor), point.committed)
    )


def fixture_account(context: Context, name: str) -> tuple[bytes, dict[str, Any]]:
    fixtures = context.image.fixtures
    if fixtures.get("result") != "NATIVE_WALLET_INDEX_FIXTURES_OK":
        raise RuntimeError("rebuild the native image with --wallet-index-fixtures")
    item = fixtures["accounts"][name]
    workchain, account = item["address"].split(":")
    value = bytes.fromhex(account)
    if workchain != "0" or len(value) != 32:
        raise RuntimeError(f"{name}: fixture account is not a basechain address")
    return value, item


def edit_injected(snapshot, dormant: bytes, template: bytes) -> JsonObject:
    """Keep a real transaction's layout, LT and references, but claim another account."""
    from pytosiq_core import Cell, begin_cell

    original = Cell.one_from_boc(template)
    fields = original.begin_parse()
    if fields.load_uint(4) != 7:
        raise RuntimeError("the injection template is not a transaction")
    original_account = fields.load_bytes(32)
    lt = fields.copy().load_uint(64)
    if original_account == dormant or snapshot.get(RECORDS.event_key(dormant, lt)) is not None:
        raise RuntimeError("the injection must add a new row under another account")
    injected = begin_cell().store_uint(7, 4).store_bytes(dormant).store_slice(fields).end_cell()
    snapshot.put(RECORDS.event_key(dormant, lt), injected.to_boc())
    return {
        "account": dormant.hex(),
        "lt": lt,
        "template_account": original_account.hex(),
        "template_hash": original.hash.hex(),
        "injected_hash": injected.hash.hex(),
    }


def edit_destroyed(snapshot, account: bytes) -> JsonObject:
    rows = snapshot.events(account)
    if not rows:
        raise RuntimeError("the destroyed account has no history to omit")
    for _, lt, _ in rows:
        snapshot.delete(RECORDS.event_key(account, lt))
    return {"account": account.hex(), "removed_lts": [lt for _, lt, _ in rows]}


def edit_recreated(snapshot, account: bytes, destroy_lt: int, new_first_lt: int) -> JsonObject:
    rows = snapshot.events(account)
    removed = [lt for _, lt, _ in rows if lt <= destroy_lt]
    retained = [lt for _, lt, _ in rows if lt >= new_first_lt]
    if not removed or not retained or len(removed) + len(retained) != len(rows):
        raise RuntimeError("the recreated fixture must contain both incarnations without overlap")
    for lt in removed:
        snapshot.delete(RECORDS.event_key(account, lt))
    return {"account": account.hex(), "removed_lts": removed, "retained_lts": retained}


def edit_forged_ownership(snapshot, owner: bytes, wallet: bytes, lt: int) -> list[bytes]:
    from pytosiq_core import begin_cell

    master = hashlib.sha256(b"wallet-index-local-fixture-false-master").digest()
    records = {
        b"\x10" + owner + master: begin_cell()
        .store_bytes(wallet)
        .store_uint(lt, 64)
        .end_cell()
        .to_boc(),
        b"\x11" + owner + wallet: begin_cell()
        .store_uint(0, 1)
        .store_uint(lt, 64)
        .end_cell()
        .to_boc(),
        b"\x13" + wallet: b"\x01" + owner + lt.to_bytes(8, "big"),
        b"\x17" + wallet: b"\x01" + owner + master + lt.to_bytes(8, "big"),
        b"\x18" + owner + master: b"\x01" + wallet + lt.to_bytes(8, "big"),
    }
    for key, value in records.items():
        snapshot.put(key, value)
    return list(records)


def refused_run(
    context: Context, out: Path, data: Path, reason: str, *, on_full=False
) -> JsonObject:
    source = context.image.full if on_full else context.image.joined
    service = run_service(
        context.service,
        source,
        data,
        ["--allow-partial-verification"],
        lambda status, body: False,
        out / "service.log",
    )
    if service.exit_code != 2:
        raise AssertionError(f"{out.name}: exit {service.exit_code}, expected 2")
    if service.ever_ready:
        raise AssertionError(f"{out.name}: the refused index was served as ready")
    matched = re.search(reason, service.log)
    if matched is None:
        raise AssertionError(f"{out.name}: refusal reason /{reason}/ not logged")
    return {
        "run": service.__dict__ | {"log": None},
        "reason": reason,
        "matched_reason": matched.group(),
        "snapshot_sha256": SNAPSHOT_RUNNER.sha256(out / "edited.snapshot"),
    }


def scenario_injected(context: Context, out: Path) -> JsonObject:
    dormant, fixture = fixture_account(context, "dormant")
    history, _ = fixture_account(context, "history")
    edit_receipt: JsonObject = {}

    def edit(snapshot):
        rows = snapshot.events(history)
        if not rows or rows[0][1] <= fixture["last_lt"]:
            raise RuntimeError("injection template is not newer than the dormant account")
        edit_receipt.update(edit_injected(snapshot, dormant, rows[0][2]))

    data = import_edited(context, out, edit)
    return {
        **refused_run(context, out, data, "rows are newer than the account's last transaction"),
        "edit": edit_receipt,
        "dormant_state": fixture,
    }


def scenario_stale(context: Context, out: Path) -> JsonObject:
    fixture_account(context, "dormant")
    checkpoint = int(context.image.fixtures["stale_checkpoint"])
    if not 0 < checkpoint < context.image.init_seqno:
        raise RuntimeError("the stale checkpoint is not older than the joined init block")
    snapshot = out / "stale.snapshot"
    tool(
        context.build,
        "--action",
        "create",
        "--index-dir",
        str(reference_at(context, checkpoint)),
        "--snapshot",
        str(snapshot),
        receipt=out / "create.log",
    )
    data = import_edited(context, out, None, original=snapshot)
    return {
        **refused_run(context, out, data, "snapshot older than this node's history"),
        "stale_checkpoint": checkpoint,
        "init_seqno": context.image.init_seqno,
    }


def scenario_destroyed(context: Context, out: Path) -> JsonObject:
    account, fixture = fixture_account(context, "destroyed")
    edit_receipt: JsonObject = {}

    def edit(snapshot):
        edit_receipt.update(edit_destroyed(snapshot, account))

    data = import_edited(context, out, edit)
    return {
        **refused_run(context, out, data, "the snapshot omits the account's history in the window"),
        "edit": edit_receipt,
        "lifecycle": fixture,
    }


def scenario_recreated(context: Context, out: Path) -> JsonObject:
    account, fixture = fixture_account(context, "recreated")
    edit_receipt: JsonObject = {}

    def edit(snapshot):
        edit_receipt.update(
            edit_recreated(snapshot, account, fixture["destroy_lt"], fixture["new_first_lt"])
        )

    data = import_edited(context, out, edit)
    return {
        **refused_run(
            context,
            out,
            data,
            "the window's blocks hold a transaction at [0-9]+ the snapshot does not match",
        ),
        "edit": edit_receipt,
        "lifecycle": fixture,
    }


def scenario_forged_ownership(context: Context, out: Path) -> JsonObject:
    owner, _ = fixture_account(context, "dormant")
    wallet, fixture = fixture_account(context, "history")
    keys: list[bytes] = []

    def edit(snapshot):
        keys.extend(edit_forged_ownership(snapshot, owner, wallet, fixture["last_lt"]))

    data = import_edited(context, out, edit)
    before = out / "quarantined.snapshot"
    tool(
        context.build,
        "--action",
        "create",
        "--index-dir",
        str(data / "index"),
        "--snapshot",
        str(before),
        receipt=out / "quarantined-create.log",
    )
    quarantined = RECORDS.parse(before.read_bytes())
    if len(keys) != 5 or any(quarantined.get(key) is not None for key in keys):
        raise AssertionError("untrusted import retained publisher ownership claims")
    run = run_service(
        context.service, context.image.joined, data, [], until_full, out / "service.log"
    )
    require_reached(run, "forged-ownership")
    head = run.readyz.get("masterchain_seqno")
    if not isinstance(head, int):
        raise RuntimeError("the rederived index reported no head")
    own, other = common_window_digests(
        context.build, data / "index", reference_at(context, head), head, out
    )
    if own.sha256 != other.sha256:
        raise AssertionError("publisher ownership claims survived authoritative derivation")
    return {
        "run": run.__dict__ | {"log": None},
        "head": head,
        "window_base": own.window_base,
        "forged_keys": [key.hex() for key in keys],
        "claims_after_import": 0,
        "snapshot_sha256": SNAPSHOT_RUNNER.sha256(out / "edited.snapshot"),
        "digests": {"rederived": own.sha256, "reference": other.sha256},
    }


@dataclass
class RedControl:
    name: str
    edit: Callable[[object], None]
    reason: str
    # Run on the full source (which holds block 1) instead of the joined one.
    on_full: bool = False


RED_CONTROLS = [
    RedControl(
        "tampered",
        edit_tampered,
        "not hash-linked|not the account's last transaction|does not decode",
    ),
    RedControl("omitted", edit_omitted, "not hash-linked"),
    RedControl("truncated", edit_truncated, "truncated inside the window|not hash-linked"),
    RedControl("wrong-checkpoint", edit_wrong_checkpoint, "not this node's masterchain block"),
    RedControl(
        "wrong-anchor", edit_wrong_anchor, "anchor is not this node's first block", on_full=True
    ),
]


def scenario_red(control: RedControl) -> Callable[[Context, Path], JsonObject]:
    def run(context: Context, out: Path) -> JsonObject:
        def edit(snapshot: object) -> None:
            if control.name in ("tampered", "omitted", "truncated"):
                account, _ = fixture_account(context, "history")
                history_edits = {
                    "tampered": edit_tampered,
                    "omitted": edit_omitted,
                    "truncated": edit_truncated,
                }
                history_edits[control.name](snapshot, account)
            else:
                control.edit(snapshot)

        data = import_edited(context, out, edit)
        return refused_run(context, out, data, control.reason, on_full=control.on_full)

    return run


SCENARIOS: dict[str, Callable[[Context, Path], JsonObject]] = {
    "reference": scenario_reference,
    "path-b": scenario_path_b,
    "path-a": scenario_path_a,
    **{control.name: scenario_red(control) for control in RED_CONTROLS},
    "injected": scenario_injected,
    "stale": scenario_stale,
    "forged-ownership": scenario_forged_ownership,
    "destroyed-omitted": scenario_destroyed,
    "recreated-omitted": scenario_recreated,
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--init-root", type=Path, required=True)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--scenarios", nargs="*", default=list(SCENARIOS))
    args = parser.parse_args()
    if not re.fullmatch("[0-9a-f]{40}", args.source_commit):
        raise ValueError("source commit must be a full Git ID")
    unknown = [name for name in args.scenarios if name not in SCENARIOS]
    if not args.scenarios or len(set(args.scenarios)) != len(args.scenarios):
        raise ValueError("at least one distinct scenario is required")
    if unknown:
        raise ValueError(f"unknown scenarios: {unknown}")
    image = discover_image(args.init_root.resolve(strict=True))
    root = args.root.resolve()
    for source in (image.full, image.joined):
        if root == source or source in root.parents or root in source.parents:
            raise ValueError("output and source directories must not overlap")
    root.mkdir(parents=True, mode=0o700, exist_ok=False)
    build = args.build.resolve(strict=True)
    service = (build / "services/tos-wallet-index").resolve(strict=True)
    before = {str(p): SNAPSHOT_RUNNER.source_inventory(p) for p in (image.full, image.joined)}
    checkpoint = int(
        image.fixtures.get("checkpoint", {}).get("seqno", image.init_seqno + CHECKPOINT_ABOVE_INIT)
    )
    context = Context(build, root, image, checkpoint, service)
    results: dict[str, object] = {
        "source_commit": args.source_commit,
        "service_sha256": SNAPSHOT_RUNNER.sha256(service),
        "image": {"full": str(image.full), "joined": str(image.joined)},
        "init_seqno": image.init_seqno,
        "checkpoint": context.checkpoint,
        "fixtures": image.fixtures,
        "binary_sha256": {
            name: SNAPSHOT_RUNNER.sha256(build / "services" / name)
            for name in ("tos-wallet-index", "tos-wallet-index-snapshot", "tos-wallet-index-dump")
        },
    }
    scenarios: dict[str, JsonObject] = {}
    results["scenarios"] = scenarios
    failed = []
    try:
        for name in args.scenarios:
            out = root / name
            out.mkdir()
            print(f"START {name}", flush=True)
            receipt: JsonObject
            try:
                receipt = {"result": "OK", **SCENARIOS[name](context, out)}
            except Unavailable as missing:
                receipt = {"result": "UNAVAILABLE", "reason": str(missing)}
                failed.append(name)
            except (
                AssertionError,
                RuntimeError,
                TimeoutError,
                OSError,
                ValueError,
                KeyError,
            ) as error:
                receipt = {"result": "FAILED", "reason": str(error)}
                failed.append(name)
            (out / "receipt.json").write_text(json.dumps(receipt, indent=2, default=str) + "\n")
            scenarios[name] = receipt
            print(f"DONE {name}: {receipt['result']}", flush=True)
    finally:
        results["sources_unchanged"] = all(
            SNAPSHOT_RUNNER.source_inventory(Path(path)) == entries
            for path, entries in before.items()
        )
        (root / "receipt.json").write_text(json.dumps(results, indent=2, default=str) + "\n")
    print(json.dumps(results, indent=2, default=str), flush=True)
    if not results["sources_unchanged"]:
        print("stopped source file metadata changed during the run", flush=True)
        return 1
    if failed:
        print(f"scenarios not passed: {failed}", flush=True)
        return 1
    print("NATIVE_WALLET_INDEX_VERIFY_OK", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
