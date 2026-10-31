"""BR1 durable relay engine, not a network/proof-verification adapter.

All network writes are behind Adapter.broadcast. An adapter must independently
validate native state/proofs and finality; a JSON-RPC success is not evidence.
No test-only signer, manual unpinned CLI fallback or automatic unknown retry is
provided. See README.md for the deliberately open production integration gates.
"""
from __future__ import annotations

import base64
import binascii
import contextlib
import dataclasses
import hashlib
import json
import os
import re
import sqlite3
import stat
import threading
import time
from pathlib import Path
from typing import Protocol

MAX_BODY = 256 * 1024
MAX_PREPARED = 512 * 1024
MAX_ACCEPTANCE = 16 * 1024
MAX_LIFETIME = 300
FR = 52435875175126190479447740508185965837690552500527637822603658699938581184513
HASH = re.compile(r"[0-9a-f]{64}\Z")
ADDRESS = re.compile(r"0:[0-9a-f]{64}\Z")
LIVE = ("reserved", "prepared", "unknown", "broadcast")
TERMINAL = ("executed", "rejected")


class Refused(ValueError):
    pass


def digest(value: str) -> str:
    if type(value) is not str or not HASH.fullmatch(value) or int(value, 16) == 0:
        raise Refused("expected a nonzero lowercase 32-byte digest")
    return value


def integer(value: int, low: int, high: int) -> int:
    if type(value) is not int or not low <= value <= high:
        raise Refused("integer out of range")
    return value


def unique_object(items):
    result = {}
    for key, value in items:
        if key in result:
            raise Refused("duplicate JSON member")
        result[key] = value
    return result


def encode(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False).encode("ascii")


@dataclasses.dataclass(frozen=True)
class Release:
    """Operator-pinned identity, not supplied by an HTTP requester or directory."""
    global_id: int
    genesis_root: str
    genesis_file: str
    bond: str
    bond_code_hash: str
    policy_hash: str
    worker_key_hash: str
    pool: str
    pool_code_hash: str
    pool_config_hash: str

    def __post_init__(self):
        integer(self.global_id, -(1 << 31), (1 << 31) - 1)
        for field in dataclasses.fields(self):
            value = getattr(self, field.name)
            if field.name == "global_id":
                continue
            if field.name in ("bond", "pool"):
                if type(value) is not str or not ADDRESS.fullmatch(value):
                    raise Refused("canonical workchain-0 address required")
            else:
                digest(value)

    @property
    def scope(self) -> str:
        return hashlib.sha256(b"TOS-BR1-RELEASE\0" + encode(dataclasses.asdict(self))).hexdigest()


@dataclasses.dataclass(frozen=True)
class Request:
    release: str
    intent: str
    body_b64: str
    body_sha256: str
    nullifiers: tuple[str, str]
    quote_hash: str
    fee_note_body: str
    fee_slot: int
    fee_note_index: int
    valid_until: int
    funding_cap: int

    def __post_init__(self):
        for name in ("release", "intent", "body_sha256", "quote_hash", "fee_note_body"):
            digest(getattr(self, name))
        if type(self.nullifiers) is not tuple or len(self.nullifiers) != 2:
            raise Refused("exactly two nullifiers required")
        for value in (*self.nullifiers, self.intent, self.fee_note_body):
            digest(value)
            if int(value, 16) >= FR:
                raise Refused("noncanonical scalar")
        if self.nullifiers[0] == self.nullifiers[1]:
            raise Refused("duplicate input nullifier")
        integer(self.fee_slot, 0, 2)
        integer(self.fee_note_index, 0, (1 << 64) - 1)
        integer(self.valid_until, 1, (1 << 32) - 1)
        integer(self.funding_cap, 1, (1 << 63) - 1)
        if type(self.body_b64) is not str or len(self.body_b64) > 4 * ((MAX_BODY + 2) // 3):
            raise Refused("body too large")
        try:
            body = base64.b64decode(self.body_b64, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise Refused("invalid body encoding") from exc
        if not body or len(body) > MAX_BODY or base64.b64encode(body).decode() != self.body_b64:
            raise Refused("noncanonical body encoding")
        if hashlib.sha256(body).hexdigest() != self.body_sha256:
            raise Refused("body bytes do not match their digest")

    @classmethod
    def parse(cls, wire: bytes) -> Request:
        if type(wire) is not bytes or len(wire) > 2 * MAX_BODY:
            raise Refused("request too large")
        try:
            obj = json.loads(wire, object_pairs_hook=unique_object,
                             parse_constant=lambda _: (_ for _ in ()).throw(Refused("nonfinite JSON")))
            if type(obj) is not dict or set(obj) != {f.name for f in dataclasses.fields(cls)}:
                raise Refused("unknown or missing request members")
            if type(obj["nullifiers"]) is not list:
                raise Refused("nullifier array required")
            obj["nullifiers"] = tuple(obj["nullifiers"])
            return cls(**obj)
        except (UnicodeError, json.JSONDecodeError, TypeError, RecursionError, OverflowError) as exc:
            raise Refused("invalid request") from exc

    @property
    def wire(self) -> bytes:
        return encode(dataclasses.asdict(self))

    @property
    def identity(self) -> str:
        return hashlib.sha256(b"TOS-BR1-REQUEST\0" + self.wire).hexdigest()


@dataclasses.dataclass(frozen=True)
class Prepared:
    """Exact signed bytes, independently checked by Adapter.validate_prepared."""
    message: bytes
    message_hash: str  # TVM representation hash, NOT sha256(serialized BOC).
    acceptance: bytes

    def __post_init__(self):
        digest(self.message_hash)
        for data, maximum in ((self.message, MAX_PREPARED), (self.acceptance, MAX_ACCEPTANCE)):
            if type(data) is not bytes or not 0 < len(data) <= maximum:
                raise Refused("prepared object outside size bound")


@dataclasses.dataclass(frozen=True)
class Evidence:
    release: str
    request: str
    message_hash: str
    outcome: str
    finalized_block: str
    proof_digest: str

    def __post_init__(self):
        for name in ("release", "request", "message_hash", "finalized_block", "proof_digest"):
            digest(getattr(self, name))
        if self.outcome not in TERMINAL:
            raise Refused("not terminal evidence")


class Adapter(Protocol):
    """Trusted release integration boundary, not an HTTP plugin chosen by users.

    preflight verifies live bond code/config/canonical identity/backing, full
    network pin, fee output and the COMPLETE exact Shield transaction/proof.
    prepare never writes to the network and signs the FC acceptance cell with
    its durable slot and issued_at. validate_prepared independently binds every
    signed field, the reserved funding bound, and locally computes the TVM message
    hash. recheck repeats
    current chain/funding/expiry checks immediately before the only write.
    evidence returns None unless destination execution or terminal refusal has
    cryptographically verified finality for this exact message and pool intent.
    """
    def preflight(self, release: Release, request: Request) -> int: ...
    def prepare(self, release: Release, request: Request, slot: int, issued_at: int,
                funding: int) -> Prepared: ...
    def validate_prepared(self, release: Release, request: Request, slot: int,
                          issued_at: int, funding: int, prepared: Prepared) -> None: ...
    def recheck(self, release: Release, request: Request, prepared: Prepared) -> None: ...
    def broadcast(self, exact_message: bytes) -> None: ...
    def evidence(self, release: Release, request: Request, prepared: Prepared) -> Evidence | None: ...


class Journal:
    def __init__(self, path: Path, release: Release, *, max_pending: int = 64,
                 max_reserved: int = 100 * 10**9):
        self.max_pending = integer(max_pending, 1, 10000)
        self.max_reserved = integer(max_reserved, 1, (1 << 63) - 1)
        self.release = release
        self.lock = threading.RLock()
        path = Path(path)
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if path.parent.stat().st_mode & 0o077:
            raise Refused("journal directory must be private (0700)")
        try:
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
            os.close(fd)
        except FileExistsError:
            st = path.lstat()
            if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or st.st_mode & 0o077:
                raise Refused("journal must be a private, nonlinked regular file")
        self.db = sqlite3.connect(path, isolation_level=None, check_same_thread=False, timeout=10)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS jobs (
                id TEXT PRIMARY KEY, request BLOB NOT NULL, slot INTEGER UNIQUE NOT NULL,
                issued INTEGER NOT NULL, funding INTEGER NOT NULL, state TEXT NOT NULL,
                message BLOB, message_hash TEXT, acceptance BLOB, evidence BLOB);
            CREATE TABLE IF NOT EXISTS input_locks (
                nullifier TEXT PRIMARY KEY, job TEXT NOT NULL REFERENCES jobs(id));
        """)
        try:
            with self.transaction():
                self.db.execute("INSERT OR IGNORE INTO metadata VALUES ('schema','1')")
                self.db.execute("INSERT OR IGNORE INTO metadata VALUES ('release',?)", (release.scope,))
                self.db.execute("INSERT OR IGNORE INTO metadata VALUES ('next_slot','1')")
                meta = dict(self.db.execute("SELECT key,value FROM metadata"))
                if meta["schema"] != "1" or meta["release"] != release.scope:
                    raise Refused("journal belongs to another schema/network/worker/release")
        except BaseException:
            self.db.close()
            raise

    @contextlib.contextmanager
    def transaction(self):
        with self.lock:
            self.db.execute("BEGIN IMMEDIATE")
            try:
                yield
                self.db.execute("COMMIT")
            except BaseException:
                self.db.execute("ROLLBACK")
                raise

    def close(self):
        self.db.close()

    def get(self, identity: str):
        digest(identity)
        with self.lock:
            return self.db.execute("SELECT * FROM jobs WHERE id=?", (identity,)).fetchone()

    def reserve(self, request: Request, funding: int, issued: int):
        integer(funding, 1, min(request.funding_cap, self.max_reserved))
        with self.transaction():
            old = self.get(request.identity)
            if old is not None:
                return old, False
            count, total = self.db.execute(
                "SELECT COUNT(*),COALESCE(SUM(funding),0) FROM jobs "
                "WHERE state IN ('reserved','prepared','unknown','broadcast')").fetchone()
            if count >= self.max_pending or total + funding > self.max_reserved:
                raise Refused("pending queue or aggregate funding cap reached")
            slot = int(self.db.execute("SELECT value FROM metadata WHERE key='next_slot'").fetchone()[0])
            integer(slot, 1, (1 << 63) - 2)
            self.db.execute("UPDATE metadata SET value=? WHERE key='next_slot'", (str(slot + 1),))
            self.db.execute("INSERT INTO jobs(id,request,slot,issued,funding,state) VALUES(?,?,?,?,?,'reserved')",
                            (request.identity, request.wire, slot, issued, funding))
            try:
                self.db.executemany("INSERT INTO input_locks VALUES (?,?)",
                                    [(n, request.identity) for n in request.nullifiers])
            except sqlite3.IntegrityError as exc:
                raise Refused("an input is already reserved or spent in this journal") from exc
            return self.get(request.identity), True

    def store_prepared(self, identity: str, value: Prepared):
        with self.transaction():
            changed = self.db.execute(
                "UPDATE jobs SET state='prepared',message=?,message_hash=?,acceptance=? "
                "WHERE id=? AND state='reserved'",
                (value.message, value.message_hash, value.acceptance, identity)).rowcount
            if changed != 1:
                raise Refused("preparation may be committed only once")

    def claim_broadcast(self, identity: str) -> bool:
        with self.transaction():
            return self.db.execute("UPDATE jobs SET state='unknown' WHERE id=? AND state='prepared'",
                                   (identity,)).rowcount == 1

    def broadcast_returned(self, identity: str):
        with self.transaction():
            self.db.execute("UPDATE jobs SET state='broadcast' WHERE id=? AND state='unknown'", (identity,))

    def finish(self, evidence: Evidence):
        with self.transaction():
            row = self.get(evidence.request)
            if row is None or row["message_hash"] != evidence.message_hash or evidence.release != self.release.scope:
                raise Refused("unrelated evidence")
            if row["state"] in TERMINAL:
                if row["state"] != evidence.outcome:
                    raise Refused("conflicting terminal evidence")
                return
            if row["state"] not in ("unknown", "broadcast"):
                raise Refused("no broadcast attempt exists")
            self.db.execute("UPDATE jobs SET state=?,evidence=? WHERE id=?",
                            (evidence.outcome, encode(dataclasses.asdict(evidence)), evidence.request))
            if evidence.outcome == "rejected":
                self.db.execute("DELETE FROM input_locks WHERE job=?", (evidence.request,))
            # Keep executed-nullifier tombstones. They are not queue/funding reservations.


class Engine:
    def __init__(self, journal: Journal, adapter: Adapter, *, clock=time.time):
        self.journal, self.adapter, self.clock = journal, adapter, clock
        self.release = journal.release

    @staticmethod
    def _prepared(row) -> Prepared:
        return Prepared(bytes(row["message"]), row["message_hash"], bytes(row["acceptance"]))

    def _request(self, row) -> Request:
        request = Request.parse(bytes(row["request"]))
        if request.identity != row["id"] or request.release != self.release.scope:
            raise Refused("persisted request identity mismatch")
        return request

    def submit(self, request: Request) -> str:
        if request.release != self.release.scope:
            raise Refused("request names another release")
        old = self.journal.get(request.identity)
        if old is not None:
            return self.dispatch(request.identity) if old["state"] == "prepared" else old["state"]
        now = int(self.clock())
        if not now < request.valid_until <= now + MAX_LIFETIME:
            raise Refused("request outside acceptance lifetime")
        funding = self.adapter.preflight(self.release, request)
        row, created = self.journal.reserve(request, funding, now)
        if not created:
            return row["state"]
        prepared = self.adapter.prepare(self.release, request, row["slot"], row["issued"], row["funding"])
        self.adapter.validate_prepared(self.release, request, row["slot"], row["issued"], row["funding"], prepared)
        self.journal.store_prepared(request.identity, prepared)
        return self.dispatch(request.identity)

    def dispatch(self, identity: str) -> str:
        row = self.journal.get(identity)
        if row is None:
            raise Refused("unknown request")
        if row["state"] != "prepared":
            return row["state"]
        request = self._request(row)
        prepared = self._prepared(row)
        # Revalidate persisted bytes too: a restart may not trust a stale adapter result.
        self.adapter.validate_prepared(self.release, request, row["slot"], row["issued"], row["funding"], prepared)
        if not self.journal.claim_broadcast(identity):
            return self.journal.get(identity)["state"]
        # Persist UNKNOWN before the first possible network write. Any exception,
        # including cancellation, keeps the exact bytes and all reservations.
        if int(self.clock()) >= request.valid_until:
            return "unknown"
        try:
            self.adapter.recheck(self.release, request, prepared)
            self.adapter.broadcast(prepared.message)
        except Exception:
            return "unknown"
        self.journal.broadcast_returned(identity)
        return self.journal.get(identity)["state"]

    def reconcile(self, identity: str) -> str:
        row = self.journal.get(identity)
        if row is None:
            raise Refused("unknown request")
        if row["state"] not in ("unknown", "broadcast"):
            return row["state"]
        request = self._request(row)
        prepared = self._prepared(row)
        evidence = self.adapter.evidence(self.release, request, prepared)
        if evidence is not None:
            self.journal.finish(evidence)
        return self.journal.get(identity)["state"]
