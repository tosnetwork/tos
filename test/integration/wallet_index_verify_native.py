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


def discover_image(init_root: Path) -> Image:
    """The full and the joined source of a stopped init-block image."""
    receipt = json.loads((init_root / "init-block-receipt.json").read_text())
    if receipt.get("result") != "NATIVE_INIT_BLOCK_JOIN_OK":
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
    return Image(stores[0], joined, int(receipt["init_block"]["seqno"]))


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


def import_edited(context: Context, out: Path, edit: Callable[[object], None] | None) -> Path:
    """Import the donor snapshot, edited by `edit`, untrusted into a new index."""
    snapshot = RECORDS.parse(donor_snapshot(context).read_bytes())
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
    raise Unavailable("the bulk window builder (stage 4c) is not in this build")


def first_account_with(snapshot, count: int) -> bytes:
    """An account with at least `count` history rows in the snapshot."""
    counts: dict[bytes, int] = {}
    for account, _, _ in snapshot.events():
        counts[account] = counts.get(account, 0) + 1
    for account, rows in sorted(counts.items()):
        if rows >= count:
            return account
    raise RuntimeError(f"the snapshot has no account with {count} history rows")


def edit_tampered(snapshot) -> None:
    account, lt, value = snapshot.events(first_account_with(snapshot, 1))[0]
    snapshot.put(RECORDS.event_key(account, lt), RECORDS.tamper_value(value))


def edit_omitted(snapshot) -> None:
    rows = snapshot.events(first_account_with(snapshot, 3))
    account, lt, _ = rows[1]
    snapshot.delete(RECORDS.event_key(account, lt))


def edit_truncated(snapshot) -> None:
    rows = snapshot.events(first_account_with(snapshot, 2))
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
        data = import_edited(context, out, control.edit)
        source = context.image.full if control.on_full else context.image.joined
        service = run_service(
            context.service,
            source,
            data,
            ["--allow-partial-verification"],
            lambda status, body: False,
            out / "service.log",
        )
        if service.exit_code != 2:
            raise AssertionError(f"{control.name}: exit {service.exit_code}, expected 2")
        if service.ever_ready:
            raise AssertionError(f"{control.name}: the refused index was served as ready")
        if re.search(control.reason, service.log) is None:
            raise AssertionError(f"{control.name}: refusal reason /{control.reason}/ not logged")
        return {"run": service.__dict__ | {"log": None}, "reason": control.reason}

    return run


def scenario_unbuilt(reason: str) -> Callable[[Context, Path], JsonObject]:
    def run(context: Context, out: Path) -> JsonObject:
        raise Unavailable(reason)

    return run


SCENARIOS: dict[str, Callable[[Context, Path], JsonObject]] = {
    "reference": scenario_reference,
    "path-b": scenario_path_b,
    "path-a": scenario_path_a,
    **{control.name: scenario_red(control) for control in RED_CONTROLS},
    "injected": scenario_unbuilt("needs an account in the image last active before the window"),
    "stale": scenario_unbuilt("needs a snapshot older than the joined source's first block"),
    "forged-ownership": scenario_unbuilt("needs the canonical dump (stage 4d)"),
    "destroyed-omitted": scenario_unbuilt("needs fixture traffic destroying an account"),
    "recreated-omitted": scenario_unbuilt("needs fixture traffic recreating an account"),
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
    context = Context(build, root, image, image.init_seqno + CHECKPOINT_ABOVE_INIT, service)
    results: dict[str, object] = {
        "source_commit": args.source_commit,
        "service_sha256": SNAPSHOT_RUNNER.sha256(service),
        "image": {"full": str(image.full), "joined": str(image.joined)},
        "init_seqno": image.init_seqno,
        "checkpoint": context.checkpoint,
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
            except (AssertionError, RuntimeError, TimeoutError, OSError) as error:
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
