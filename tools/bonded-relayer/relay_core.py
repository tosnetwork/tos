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
TERMINAL = ("executed", "rejected", "cancelled")
EVIDENCE_WINDOW = 86400
MAX_QUOTE = 32 * 1024


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


def checked_add(a: int, b: int, maximum: int) -> int:
    integer(a, 0, maximum)
    integer(b, 0, maximum)
    if a > maximum - b:
        raise Refused("bounded addition overflow")
    return a + b


def unique_object(items):
    result = {}
    for key, value in items:
        if key in result:
            raise Refused("duplicate JSON member")
        result[key] = value
    return result


def encode(obj: dict) -> bytes:
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("ascii")


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
            obj = json.loads(
                wire,
                object_pairs_hook=unique_object,
                parse_constant=lambda _: (_ for _ in ()).throw(Refused("nonfinite JSON")),
            )
            if type(obj) is not dict or set(obj) != {f.name for f in dataclasses.fields(cls)}:
                raise Refused("unknown or missing request members")
            if type(obj["nullifiers"]) is not list:
                raise Refused("nullifier array required")
            obj["nullifiers"] = tuple(obj["nullifiers"])
            return cls(**obj)
        except (
            UnicodeError,
            json.JSONDecodeError,
            TypeError,
            RecursionError,
            OverflowError,
        ) as exc:
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
    fee_credit: dict | None = None

    def __post_init__(self):
        for name in ("release", "request", "message_hash", "finalized_block", "proof_digest"):
            digest(getattr(self, name))
        if self.fee_credit is not None and (
            type(self.fee_credit) is not dict or len(encode(self.fee_credit)) > 8192
        ):
            raise Refused("fee credit shape/size")
        if self.outcome not in ("executed", "rejected"):
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
    def prepare(
        self, release: Release, request: Request, slot: int, issued_at: int, funding: int
    ) -> Prepared: ...
    def validate_prepared(
        self,
        release: Release,
        request: Request,
        slot: int,
        issued_at: int,
        funding: int,
        prepared: Prepared,
    ) -> None: ...
    def recheck(self, release: Release, request: Request, prepared: Prepared) -> None: ...
    def broadcast(self, exact_message: bytes) -> None: ...
    def evidence(
        self, release: Release, request: Request, prepared: Prepared
    ) -> Evidence | None: ...


class Journal:
    def __init__(
        self,
        path: Path,
        release: Release,
        *,
        max_pending: int = 64,
        max_reserved: int = 100 * 10**9,
        max_history: int = 4096,
        max_quotes: int = 1024,
        max_disk_bytes: int = 512 * 1024 * 1024,
        require_quotes: bool = False,
    ):
        self.max_history = integer(max_history, 1, 100000)
        self.max_quotes = integer(max_quotes, 1, 10000)
        self.max_disk_bytes = integer(max_disk_bytes, 16 * 1024 * 1024, 4 * 1024**3)
        if type(require_quotes) is not bool:
            raise Refused("invalid quote policy")
        self.require_quotes = require_quotes
        self.max_pending = integer(max_pending, 1, 10000)
        self.max_reserved = integer(max_reserved, 1, (1 << 63) - 1)
        self.release = release
        self.lock = threading.RLock()
        path = Path(path).absolute()
        self.path = path
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
        # Refuse linked sidecars before SQLite is allowed to open them.
        for suffix in ("-wal", "-shm", "-journal"):
            sidecar = Path(str(path) + suffix)
            if sidecar.exists() or sidecar.is_symlink():
                st = sidecar.lstat()
                if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or st.st_mode & 0o077:
                    raise Refused("unsafe SQLite sidecar")
        self.db = sqlite3.connect(path, isolation_level=None, check_same_thread=False, timeout=10)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.execute("PRAGMA wal_autocheckpoint=128")
        self.db.execute("PRAGMA journal_size_limit=1048576")
        page_size = self.db.execute("PRAGMA page_size").fetchone()[0]
        self.db.execute(f"PRAGMA max_page_count={self.max_disk_bytes // 2 // page_size}")
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS jobs (
                id TEXT PRIMARY KEY, request BLOB NOT NULL, slot INTEGER UNIQUE NOT NULL,
                issued INTEGER NOT NULL, funding INTEGER NOT NULL, state TEXT NOT NULL,
                message BLOB, message_hash TEXT, acceptance BLOB, evidence BLOB);
            CREATE TABLE IF NOT EXISTS quotes (
                id TEXT PRIMARY KEY, note_index INTEGER UNIQUE NOT NULL,
                created INTEGER NOT NULL, expires INTEGER NOT NULL,
                terms BLOB, signed BLOB, state TEXT NOT NULL,
                job TEXT UNIQUE REFERENCES jobs(id));
            CREATE TABLE IF NOT EXISTS input_locks (
                nullifier TEXT PRIMARY KEY, job TEXT NOT NULL REFERENCES jobs(id));
        """)
        try:
            with self.transaction():
                self.db.execute("INSERT OR IGNORE INTO metadata VALUES ('schema','1')")
                self.db.execute(
                    "INSERT OR IGNORE INTO metadata VALUES ('release',?)", (release.scope,)
                )
                self.db.execute("INSERT OR IGNORE INTO metadata VALUES ('next_slot','1')")
                self.db.execute("INSERT OR IGNORE INTO metadata VALUES ('next_note_index','0')")
                # Additive schema migration: no counters, receipts or locks are reset.
                self.db.execute("UPDATE metadata SET value='2' WHERE key='schema' AND value='1'")
                meta = dict(self.db.execute("SELECT key,value FROM metadata"))
                if meta["schema"] != "2" or meta["release"] != release.scope:
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
                if self.db.in_transaction:
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
                "WHERE state IN ('reserved','prepared','unknown','broadcast')"
            ).fetchone()
            if (
                count >= self.max_pending
                or checked_add(total, funding, (1 << 63) - 1) > self.max_reserved
            ):
                raise Refused("pending queue or aggregate funding cap reached")
            self._admission_budget()
            if self.require_quotes:
                self._match_quote(request, issued)
            slot = int(
                self.db.execute("SELECT value FROM metadata WHERE key='next_slot'").fetchone()[0]
            )
            integer(slot, 1, (1 << 63) - 2)
            self.db.execute(
                "UPDATE metadata SET value=? WHERE key='next_slot'",
                (str(checked_add(slot, 1, (1 << 63) - 1)),),
            )
            self.db.execute(
                "INSERT INTO jobs(id,request,slot,issued,funding,state) VALUES(?,?,?,?,?,'reserved')",
                (request.identity, request.wire, slot, issued, funding),
            )
            try:
                self.db.executemany(
                    "INSERT INTO input_locks VALUES (?,?)",
                    [(n, request.identity) for n in request.nullifiers],
                )
            except sqlite3.IntegrityError as exc:
                raise Refused("an input is already reserved or spent in this journal") from exc
            if self.require_quotes:
                changed = self.db.execute(
                    "UPDATE quotes SET state='claimed',job=? WHERE id=? AND state='ready'",
                    (request.identity, request.quote_hash),
                ).rowcount
                if changed != 1:
                    raise Refused("quote already claimed")
            return self.get(request.identity), True

    def store_prepared(self, identity: str, value: Prepared):
        with self.transaction():
            changed = self.db.execute(
                "UPDATE jobs SET state='prepared',message=?,message_hash=?,acceptance=? "
                "WHERE id=? AND state='reserved'",
                (value.message, value.message_hash, value.acceptance, identity),
            ).rowcount
            if changed != 1:
                raise Refused("preparation may be committed only once")

    def claim_broadcast(self, identity: str) -> bool:
        with self.transaction():
            return (
                self.db.execute(
                    "UPDATE jobs SET state='unknown' WHERE id=? AND state='prepared'", (identity,)
                ).rowcount
                == 1
            )

    def broadcast_returned(self, identity: str):
        with self.transaction():
            self.db.execute(
                "UPDATE jobs SET state='broadcast' WHERE id=? AND state='unknown'", (identity,)
            )

    def finish(self, evidence: Evidence):
        with self.transaction():
            row = self.get(evidence.request)
            if (
                row is None
                or row["message_hash"] != evidence.message_hash
                or evidence.release != self.release.scope
            ):
                raise Refused("unrelated evidence")
            if self.require_quotes and evidence.outcome == "executed":
                request = Request.parse(bytes(row["request"]))
                fee = evidence.fee_credit
                if type(fee) is not dict or fee.get("schema") != "tos.relayer.fee-credit.v1":
                    raise Refused("executed production receipt lacks verified fee credit")
                if (
                    fee.get("note_body") != request.fee_note_body
                    or fee.get("note_key_index") != request.fee_note_index
                    or fee.get("slot") != request.fee_slot
                    or fee.get("checkpoint_root") != evidence.finalized_block
                ):
                    raise Refused("fee credit identity mismatch")
                integer(fee.get("leaf_index"), 0, (1 << 32) - 1)
                digest(fee.get("transaction"))
                quote = json.loads(self.quote(request.quote_hash), object_pairs_hook=unique_object)
                if fee.get("amount") != str(quote["terms"]["amount"]):
                    raise Refused("fee credit amount mismatch")
            if row["state"] in TERMINAL:
                if row["state"] != evidence.outcome:
                    raise Refused("conflicting terminal evidence")
                return
            if row["state"] not in ("unknown", "broadcast"):
                raise Refused("no broadcast attempt exists")
            self.db.execute(
                "UPDATE jobs SET state=?,evidence=? WHERE id=?",
                (evidence.outcome, encode(dataclasses.asdict(evidence)), evidence.request),
            )
            if evidence.outcome == "rejected":
                self.db.execute("DELETE FROM input_locks WHERE job=?", (evidence.request,))
            # Keep executed-nullifier tombstones. They are not queue/funding reservations.

    def _admission_budget(self):
        # Never discard identity/slot/nullifier tombstones to make room. A full
        # worker is drained and retired; a fresh worker gets a fresh journal.
        count = self.db.execute("SELECT COUNT(*) FROM jobs").fetchone()[0]
        if count >= self.max_history:
            raise Refused("worker history quota reached; drain and retire this worker")
        used = sum(
            candidate.stat().st_size
            for candidate in (
                self.path,
                Path(str(self.path) + "-wal"),
                Path(str(self.path) + "-shm"),
            )
            if candidate.exists()
        )
        # Keep space for every admitted job to commit its largest possible
        # prepared object and terminal evidence even when admission is stopped.
        headroom = (self.max_pending + 2) * (MAX_PREPARED + MAX_BODY * 2 + MAX_ACCEPTANCE)
        if used + headroom >= self.max_disk_bytes:
            raise Refused("journal disk admission quota reached")

    def allocate_quote(self, now: int, lifetime: int = MAX_LIFETIME) -> tuple[str, int]:
        integer(now, 1, (1 << 32) - 1)
        integer(lifetime, 1, MAX_LIFETIME)
        expires = checked_add(now, lifetime, (1 << 32) - 1)
        with self.transaction():
            self._admission_budget()
            self.db.execute("DELETE FROM quotes WHERE expires < ? AND job IS NULL", (now,))
            count = self.db.execute("SELECT COUNT(*) FROM quotes WHERE job IS NULL").fetchone()[0]
            if count >= self.max_quotes:
                raise Refused("quote queue quota reached")
            index = int(
                self.db.execute(
                    "SELECT value FROM metadata WHERE key='next_note_index'"
                ).fetchone()[0]
            )
            integer(index, 0, (1 << 63) - 2)
            quote_id = hashlib.sha256(os.urandom(32)).hexdigest()
            self.db.execute(
                "UPDATE metadata SET value=? WHERE key='next_note_index'",
                (str(checked_add(index, 1, (1 << 63) - 1)),),
            )
            self.db.execute(
                "INSERT INTO quotes(id,note_index,created,expires,state) "
                "VALUES(?,?,?,?,'allocated')",
                (quote_id, index, now, expires),
            )
            return quote_id, index

    def publish_quote(self, allocation: str, terms: dict, signed: bytes) -> str:
        # The local adapter signs these exact terms. Allocation is consumed even
        # if signing crashes; a receiving key index is never recycled.
        digest(allocation)
        if type(signed) is not bytes or not 0 < len(signed) <= MAX_QUOTE:
            raise Refused("invalid signed quote size")
        wire = encode(terms)
        if len(wire) > MAX_QUOTE:
            raise Refused("quote too large")
        identity = hashlib.sha256(b"TOS-BR1-QUOTE\0" + wire).hexdigest()
        with self.transaction():
            row = self.db.execute("SELECT * FROM quotes WHERE id=?", (allocation,)).fetchone()
            if row is None or row["state"] != "allocated":
                raise Refused("no unused quote allocation")
            if (
                terms.get("release") != self.release.scope
                or terms.get("nonce") != allocation
                or terms.get("note_index") != row["note_index"]
                or terms.get("issued_at") != row["created"]
                or terms.get("valid_until") != row["expires"]
            ):
                raise Refused("quote does not match its durable allocation")
            integer(terms.get("slot"), 0, 2)
            integer(terms.get("amount"), 1, (1 << 63) - 1)
            integer(terms.get("funding_cap"), 1, self.max_reserved)
            self.db.execute(
                "UPDATE quotes SET id=?,terms=?,signed=?,state='ready' WHERE id=?",
                (identity, wire, signed, allocation),
            )
        return identity

    def quote(self, identity: str) -> bytes:
        digest(identity)
        with self.lock:
            row = self.db.execute("SELECT signed FROM quotes WHERE id=?", (identity,)).fetchone()
            if row is None or row["signed"] is None:
                raise Refused("unknown quote")
            return bytes(row["signed"])

    def _match_quote(self, request: Request, now: int):
        row = self.db.execute("SELECT * FROM quotes WHERE id=?", (request.quote_hash,)).fetchone()
        if row is None or row["state"] != "ready" or row["expires"] <= now:
            raise Refused("quote unavailable or expired")
        terms = json.loads(row["terms"], object_pairs_hook=unique_object)
        if (
            request.fee_slot != terms["slot"]
            or request.fee_note_index != terms["note_index"]
            or request.valid_until > terms["valid_until"]
            or request.funding_cap > terms["funding_cap"]
        ):
            raise Refused("request changed the accepted quote")

    def cancel_unprepared(self, identity: str, now: int):
        # A RESERVED record has never passed store_prepared/claim_broadcast.
        # Neither the journal nor the pure signing adapter may write it to the
        # network. Keep its ID and slot forever; unknown/prepared attempts are
        # deliberately not recoverable through this administrative operation.
        integer(now, 1, (1 << 32) - 1)
        with self.transaction():
            row = self.get(identity)
            if row is None or row["state"] != "reserved" or row["message"] is not None:
                raise Refused("only an unprepared reservation can be cancelled")
            request = Request.parse(bytes(row["request"]))
            if request.identity != identity or request.valid_until >= now:
                raise Refused("reservation has not expired or is corrupted")
            self.db.execute("UPDATE jobs SET state='cancelled' WHERE id=?", (identity,))
            self.db.execute("DELETE FROM input_locks WHERE job=?", (identity,))

    def compact(self, now: int) -> int:
        integer(now, 1, (1 << 32) - 1)
        with self.transaction():
            rows = self.db.execute(
                "SELECT id,issued,request FROM jobs "
                "WHERE state IN ('executed','rejected','cancelled') "
                "AND message IS NOT NULL"
            ).fetchall()
            count = 0
            for row in rows:
                request = Request.parse(bytes(row["request"]))
                if now <= max(request.valid_until, row["issued"] + EVIDENCE_WINDOW):
                    continue
                # Requests retain the exact intent and input tombstones; signed
                # bearer messages and signatures may now be dropped. They are
                # neither live work nor admissible conflict evidence any longer.
                self.db.execute(
                    "UPDATE jobs SET message=NULL,acceptance=NULL WHERE id=?", (row["id"],)
                )
                self.db.execute("DELETE FROM quotes WHERE job=?", (row["id"],))
                count += 1
        with self.lock:
            self.db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        return count

    def pending(self, limit: int = 64) -> list[str]:
        integer(limit, 1, 10000)
        with self.lock:
            return [
                row[0]
                for row in self.db.execute(
                    "SELECT id FROM jobs WHERE state IN ('reserved','prepared','unknown','broadcast') "
                    "ORDER BY slot LIMIT ?",
                    (limit,),
                )
            ]

    def metrics(self) -> dict:
        with self.lock:
            counts = dict(self.db.execute("SELECT state,COUNT(*) FROM jobs GROUP BY state"))
            count = self.db.execute("SELECT COUNT(*) FROM jobs").fetchone()[0]
            return {"jobs": count, "history_limit": self.max_history, "states": counts}


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
        prepared = self.adapter.prepare(
            self.release, request, row["slot"], row["issued"], row["funding"]
        )
        self.adapter.validate_prepared(
            self.release, request, row["slot"], row["issued"], row["funding"], prepared
        )
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
        self.adapter.validate_prepared(
            self.release, request, row["slot"], row["issued"], row["funding"], prepared
        )
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
