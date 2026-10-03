#!/usr/bin/env python3
"""Experimental offline wallet. Uses locally reviewed snapshots; never activates a network."""

# Repository-local imports require the explicit path bootstrap below.
# ruff: noqa: E402

import argparse
import getpass
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "test/tostester/src"))
from backend import Backend
from backup import association, encrypt, restore, unique
from contract.falcon_auth import Falcon512ModuleBlueprint
from provider import AuthProvider, TrustedChainSnapshot
from pytosiq_core import Address, Cell


def read_json(path):
    raw = Path(path).read_bytes()
    if len(raw) > 1_000_000:
        raise ValueError("input document exceeds offline limit")
    return json.loads(raw, object_pairs_hook=unique)


def write_new(path, raw):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as f:
        f.write(raw)
        f.flush()
        os.fsync(f.fileno())


def boc(raw):
    if type(raw) is not str or len(raw) > 500_000:
        raise ValueError("oversized BOC")
    return Cell.one_from_boc(bytes.fromhex(raw))


def snapshot(document):
    fields = {
        "network",
        "global_version",
        "now",
        "account",
        "account_code",
        "account_data",
        "root",
        "module_code",
        "module_data",
        "account_status",
        "module_status",
    }
    if set(document) != fields:
        raise ValueError("incomplete reviewed snapshot")
    values = dict(document)
    for key in ("account", "root"):
        values[key] = Address(values[key])
    for key in ("account_code", "account_data", "module_code", "module_data"):
        values[key] = boc(values[key])
    return TrustedChainSnapshot(**values)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--library", type=Path, required=True)
    sub = p.add_subparsers(dest="command", required=True)
    g = sub.add_parser("generate")
    g.add_argument("--module-code", type=Path, required=True)
    g.add_argument("--manifest", type=Path, required=True)
    g.add_argument("--network", type=int, required=True)
    g.add_argument("--account", required=True)
    g.add_argument("--workchain", type=int, choices=(-1, 0), required=True)
    g.add_argument("--backup", type=Path, required=True)
    g.add_argument("--public-out", type=Path, required=True)
    d = sub.add_parser("describe")
    d.add_argument("--snapshot", type=Path, required=True)
    d.add_argument("--manifest", type=Path, required=True)
    s = sub.add_parser("sign-submit")
    s.add_argument("--snapshot", type=Path, required=True)
    s.add_argument("--manifest", type=Path, required=True)
    s.add_argument("--backup", type=Path, required=True)
    s.add_argument("--intent", type=Path, required=True)
    s.add_argument("--relayer", required=True)
    s.add_argument("--funding", type=int, required=True)
    s.add_argument("--ed25519-cosignature")
    s.add_argument("--out", type=Path, required=True)
    a = p.parse_args()
    backend = Backend(a.library)
    provider = AuthProvider(backend, read_json(a.manifest))
    if a.command == "generate":
        code = Cell.one_from_boc(a.module_code.read_bytes())
        allowed = [provider.manifest[k]["code_hash"] for k in ("module-func", "module-tol")]
        if code.hash.hex() not in allowed:
            raise ValueError("unknown module code")
        if Address(a.account).wc != a.workchain:
            raise ValueError("account workchain mismatch")
        password = getpass.getpass("New PQ backup password (at least 12 bytes): ").encode()
        if password != getpass.getpass("Repeat password: ").encode():
            raise ValueError("password mismatch")
        with provider.generateKey() as key:
            module = Falcon512ModuleBlueprint(
                code, a.workchain, a.network, key.public_key, backend.validate_public_key
            )
            root = module.address.to_str(is_user_friendly=False)
            encrypted = encrypt(key, password, a.network, a.account, root)
            with restore(
                encrypted, password, backend, association(a.network, a.account, root)
            ) as recovered:
                if recovered.public_key != key.public_key:
                    raise ValueError("backup rehearsal failed")
            public = dict(
                profile="TOS-FALCON512-PADDED-v1",
                network=a.network,
                root=root,
                account=a.account,
                public_key=key.public_key.hex(),
                state_init=module.state_init.serialize().to_boc().hex(),
                warning="Independent PQ key: the legacy 24 words do not recover it. Experimental; funding/bounces can remain in the immutable module.",
            )
            # Never replace an existing wallet or backup.
            if a.backup.exists() or a.public_out.exists():
                raise ValueError("output already exists")
            write_new(a.backup, encrypted)
            write_new(a.public_out, json.dumps(public, indent=2).encode() + b"\n")
        print("Encrypted backup recovered and public StateInit written.")
        return
    state = snapshot(read_json(a.snapshot))
    if a.command == "describe":
        from dataclasses import asdict

        print(json.dumps(asdict(provider.describe(state)), indent=2))
        return
    intent = read_json(a.intent)
    intent["payload"] = boc(intent["payload"])
    request = provider.buildSigningRequest(state, state.account, intent)
    # Display the reconstructed request for offline operator review.
    print(
        json.dumps(
            dict(
                network=state.network,
                account=state.account.to_str(is_user_friendly=False),
                root=state.root.to_str(is_user_friendly=False),
                epoch=request.request.epoch,
                nonce=request.request.nonce,
                valid_until=request.request.valid_until,
                kind=request.request.kind,
                payload_hash=request.request.payload.hash.hex(),
                commitment=request.request.commitment.hex(),
            ),
            indent=2,
        )
    )
    password = getpass.getpass("PQ backup password: ").encode()
    expected = association(
        state.network,
        state.account.to_str(is_user_friendly=False),
        state.root.to_str(is_user_friendly=False),
    )
    with restore(a.backup.read_bytes(), password, backend, expected) as key:
        proof = provider.sign(key, request)
        cosign = None if a.ed25519_cosignature is None else bytes.fromhex(a.ed25519_cosignature)
        message = provider.fundedSubmission(request, proof, Address(a.relayer), a.funding, cosign)
        write_new(a.out, message.serialize().to_boc())
    print("Funded internal submission written; awaiting relayer and target receipts.")


if __name__ == "__main__":
    try:
        main()
    except Exception:
        # Avoid printing exceptions that could incorporate secret-bearing data.
        print(
            "Offline wallet operation failed; check profile, snapshot, backup and funding.",
            file=sys.stderr,
        )
        sys.exit(1)
