"""BR1 client transport with explicit quote verification and no write retries.

This does not generate Shield witnesses or authenticate finality by itself.
A status receipt is an operator claim until independently verified on the chain.
"""

from __future__ import annotations

import base64
import dataclasses
import hashlib
import secrets
import socket
import ssl
import time
from urllib.parse import urlsplit

from relay_core import (
    LIVE,
    MAX_ACCEPTANCE,
    MAX_QUOTE,
    TERMINAL,
    Refused,
    Release,
    Request,
    digest,
    encode,
    integer,
)
from relay_http import RESPONSE_LIMIT, receive, remaining
from relay_wire import BODY_LIMIT, check_terms, exact, parse, status_hash
from tor_transport import OnionEndpoint, TorProxy


class ClientError(Refused):
    pass


class RelayerRefused(ClientError):
    """The relayer answered with a well-formed HTTP status other than 200/202. Distinct from
    an unavailable transport; a submit still reports it as SubmissionUnknown."""

    def __init__(self, status: int):
        super().__init__(f"relayer refused the request (HTTP {status})")
        self.status = status


class SubmissionUnknown(ClientError):
    def __init__(self, identity: str):
        super().__init__("submission result unavailable; reconcile this request identity")
        self.request_id = identity


@dataclasses.dataclass(frozen=True)
class Quote:
    identity: str
    terms: dict
    envelope: bytes
    status_token: str


class Client:
    def __init__(
        self,
        endpoint: str,
        release: str,
        verifier,
        *,
        allow_loopback: bool = False,
        timeout: int = 10,
        tor: TorProxy | None = None,
        clock=time.time,
    ):
        digest(release)
        self.tor = tor
        self.onion = OnionEndpoint.parse(endpoint) if tor is not None else None
        parsed = urlsplit(endpoint)
        if (
            parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or parsed.path not in ("", "/")
        ):
            raise ClientError("endpoint must be an origin without credentials")
        if tor is not None:
            if allow_loopback:
                raise ClientError("Tor and loopback test mode are mutually exclusive")
        elif parsed.scheme == "http":
            if not allow_loopback or parsed.hostname != "127.0.0.1":
                raise ClientError("plaintext HTTP is only available for explicit loopback tests")
        elif parsed.scheme != "https":
            raise ClientError("HTTPS endpoint required")
        if not parsed.hostname or any(c.isspace() for c in endpoint):
            raise ClientError("invalid endpoint host")
        # A fully qualified name keeps its trailing dot in the parsed host ("x.onion."),
        # which would slip past the onion suffix test below and reach the OS resolver.
        if parsed.hostname.endswith("."):
            raise ClientError("endpoint host must not end with a dot")
        if tor is None and parsed.hostname.endswith(".onion"):
            raise ClientError("onion endpoints require explicit Tor transport")
        self.host = parsed.hostname
        self.port = parsed.port or (443 if parsed.scheme == "https" else 80)
        self.secure = parsed.scheme == "https"
        self.release, self.verifier, self.clock = release, verifier, clock
        self.timeout = integer(timeout, 1, 60)

    @classmethod
    def from_bond(cls, release: Release, bond_init: bytes, rpc, *, tor: TorProxy, timeout=60):
        """Authenticate a public StateInit against wallet-pinned release data locally.

        rpc must be NativeRPC over a PinnedProgram, never a remote RPC server.
        No operator custody files or network reads are needed by these operations.
        This proves immutable identity, not current Bond eligibility or finality.
        """
        from native_process import NativeRPC

        if not isinstance(rpc, NativeRPC):
            raise ClientError("pinned local native verifier required")
        if type(bond_init) is not bytes or not 0 < len(bond_init) <= 65536:
            raise ClientError("Bond StateInit outside bound")
        payload = {
            "release": dataclasses.asdict(release),
            "bond_init_b64": base64.b64encode(bond_init).decode("ascii"),
        }
        identity = rpc.call("client_identity", payload)
        exact(identity, {"scope", "endpoint", "worker_key_hash"})
        if (
            identity["scope"] != release.scope
            or identity["worker_key_hash"] != release.worker_key_hash
        ):
            raise ClientError("Bond identity does not match wallet release")
        OnionEndpoint.parse(identity["endpoint"])

        def verify(wire):
            result = rpc.call("client_quote", {**payload, "envelope": parse(wire, MAX_QUOTE)})
            exact(result, {"terms"})
            return result["terms"]

        return cls(identity["endpoint"], release.scope, verify, tor=tor, timeout=timeout)

    def _request(self, path: str, payload: dict) -> dict:
        wire = encode(payload)
        if len(wire) > BODY_LIMIT:
            raise ClientError("request exceeds body bound")
        deadline = time.monotonic() + self.timeout
        connection = None
        try:
            if self.tor is not None:
                connection = self.tor.connect(self.onion, deadline)
            else:
                connection = socket.create_connection((self.host, self.port), timeout=self.timeout)
            if self.secure:
                remaining(connection, deadline)
                connection = ssl.create_default_context().wrap_socket(
                    connection, server_hostname=self.host
                )
            host = f"[{self.host}]" if ":" in self.host else self.host
            authority = self.onion.authority if self.onion is not None else f"{host}:{self.port}"
            head = (
                f"POST {path} HTTP/1.1\r\nHost: {authority}\r\n"
                "Content-Type: application/json\r\nConnection: close\r\n"
                f"Content-Length: {len(wire)}\r\n\r\n"
            ).encode("ascii")
            remaining(connection, deadline)
            connection.sendall(head + wire)
            line, _, body = receive(connection, RESPONSE_LIMIT, deadline)
            parts = line.split(" ", 2)
            if (
                len(parts) != 3
                or parts[0] != "HTTP/1.1"
                or len(parts[1]) != 3
                or not parts[1].isascii()
                or not parts[1].isdigit()
                or parts[1][0] not in "12345"
            ):
                # A malformed status line is not an answer from the relayer.
                raise ClientError("relayer returned a malformed status line")
            if parts[1] not in ("200", "202"):
                raise RelayerRefused(int(parts[1]))
            return parse(body, RESPONSE_LIMIT)
        except RelayerRefused:
            raise
        except (OSError, ValueError, Refused) as error:
            raise ClientError("relayer response unavailable") from error
        finally:
            if connection is not None:
                connection.close()

    def _verify(self, wire: bytes) -> dict:
        if self.verifier is None:
            raise ClientError("a local pinned quote verifier is required")
        if type(wire) is not bytes or not 0 < len(wire) <= MAX_QUOTE:
            raise ClientError("quote envelope outside bound")
        try:
            terms = self.verifier(wire)
        except Exception as error:
            raise ClientError("quote authentication unavailable") from error
        if type(terms) is not dict:
            raise ClientError("quote verifier did not authenticate terms")
        return terms

    def quote(self, *, slot: int = 2, lifetime: int = 300, token: str | None = None) -> Quote:
        if self.verifier is None:
            raise ClientError("a local pinned quote verifier is required")
        token = secrets.token_hex(32) if token is None else token
        access = status_hash(token)
        integer(slot, 0, 2)
        integer(lifetime, 1, 300)
        result = self._request(
            "/v1/quote", {"slot": slot, "lifetime": lifetime, "status_token": token}
        )
        exact(result, {"schema", "quote_id", "quote"})
        if result["schema"] != "tos.br1.quote.response.v1" or type(result["quote"]) is not dict:
            raise ClientError("unexpected quote response")
        wire = encode(result["quote"])
        if len(wire) > MAX_QUOTE:
            raise ClientError("quote envelope too large")
        terms = self._verify(wire)
        check_terms(terms, self.release)
        if encode(terms) != encode(result["quote"].get("terms")):
            raise ClientError("verifier returned different terms")
        identity = hashlib.sha256(b"TOS-BR1-QUOTE\0" + encode(terms)).hexdigest()
        now = int(self.clock())
        if (
            identity != result["quote_id"]
            or terms["status_hash"] != access
            or terms["slot"] != slot
            or terms["valid_until"] - terms["issued_at"] != lifetime
            or not terms["issued_at"] <= now < terms["valid_until"]
        ):
            raise ClientError("quote binding or lifetime mismatch")
        return Quote(identity, terms, wire, token)

    def submit(self, request: Request, quote: Quote) -> dict:
        if self.verifier is None:
            raise ClientError("a local pinned quote verifier is required")
        authenticated = self._verify(quote.envelope)
        if (
            encode(authenticated) != encode(quote.terms)
            or hashlib.sha256(b"TOS-BR1-QUOTE\0" + encode(authenticated)).hexdigest()
            != quote.identity
            or authenticated.get("status_hash") != status_hash(quote.status_token)
        ):
            raise ClientError("quote object is not authenticated")
        check_terms(quote.terms, self.release)
        if (
            request.release != self.release
            or request.quote_hash != quote.identity
            or request.fee_slot != quote.terms["slot"]
            or request.fee_note_index != quote.terms["note_index"]
            or request.valid_until > quote.terms["valid_until"]
            or request.funding_cap > quote.terms["funding_cap"]
            or request.valid_until <= int(self.clock())
        ):
            raise ClientError("candidate does not match the selected quote")
        try:
            response = self._request(
                "/v1/submit",
                {"request": dataclasses.asdict(request), "status_token": quote.status_token},
            )
            return self._status(response, request.identity)
        except (OSError, Refused, TypeError, KeyError) as error:
            # No automatic POST retry or new transaction construction. The caller
            # already has the identity needed to recover a lost acknowledgement.
            raise SubmissionUnknown(request.identity) from error

    def status(self, identity: str, token: str) -> dict:
        digest(identity)
        status_hash(token)
        return self._status(
            self._request("/v1/status", {"request_id": identity, "status_token": token}), identity
        )

    def _status(self, value: dict, identity: str) -> dict:
        exact(
            value,
            {
                "schema",
                "request_id",
                "release",
                "status",
                "message_hash",
                "acceptance_b64",
                "finality",
                "requires_independent_verification",
            },
        )
        if (
            value["schema"] != "tos.br1.status.v1"
            or value["request_id"] != identity
            or value["release"] != self.release
            or value["status"] not in (*LIVE, *TERMINAL)
            or value["requires_independent_verification"] is not True
        ):
            raise ClientError("status identity or semantics mismatch")
        if value["message_hash"] is not None:
            digest(value["message_hash"])
        if value["acceptance_b64"] is not None:
            text = value["acceptance_b64"]
            if type(text) is not str or len(text) > 4 * ((MAX_ACCEPTANCE + 2) // 3):
                raise ClientError("acceptance outside bound")
            data = base64.b64decode(text, validate=True)
            if not data or len(data) > MAX_ACCEPTANCE or base64.b64encode(data).decode() != text:
                raise ClientError("invalid acceptance encoding")
        if value["status"] in ("executed", "rejected"):
            if type(value["finality"]) is not dict:
                raise ClientError("terminal status lacks proof locator")
            exact(value["finality"], {"checkpoint_root", "proof_digest"})
            for field in value["finality"].values():
                digest(field)
        elif value["finality"] is not None:
            raise ClientError("nonterminal status carries finality")
        return value
