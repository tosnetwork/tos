"""Runtime boundaries that accompany the Python type-check repair."""

import asyncio
import importlib.util
import json
import shlex
import subprocess
import sys
from pathlib import Path

import pytest
from contract.pq_auth import AuthState, byte_chain
from contract.pq_lite_transport import LiteClientTransport, WalletV5Signer
from contract.wallet_v5 import WalletV5State
from nacl.public import PrivateKey
from nacl.signing import SigningKey
from pytosiq_core import Address, Builder, Cell, ExternalAddress
from pytosiq_core.boc.slice import SliceError
from pytosiq_core.boc.tvm_bitarray import TvmBitarray, TvmBitarrayOverflowException
from pytosiq_core.boc.utils import bin_to_signed_int
from pytosiq_core.crypto.ciphers import Client, Server, get_shared_key
from pytosiq_core.tl.block import BlockIdExt
from pytosiq_core.tl.generator import TlError, TlGenerator, TlSchema
from pytosiq_core.tlb.tlb import TlbError, require

ROOT = Path(__file__).resolve().parents[4]


@pytest.fixture
def wire_codec(monkeypatch):
    spec = importlib.util.spec_from_file_location("cells", ROOT / "test/auth-extensions/cells.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, "cells", module)
    spec.loader.exec_module(module)
    return module


def test_type_checker_rejects_an_actual_assignment_error(tmp_path):
    probe = tmp_path / "type_control.py"
    probe.write_text('TYPE_CONTROL: str = "valid"\n')
    good = subprocess.run(
        ["uv", "run", "basedpyright", "--outputjson", str(probe)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert good.returncode == 0, good.stderr
    assert json.loads(good.stdout)["summary"]["errorCount"] == 0
    probe.write_text("TYPE_CONTROL: str = 17\n")
    bad = subprocess.run(
        ["uv", "run", "basedpyright", "--outputjson", str(probe)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    errors = [d for d in json.loads(bad.stdout)["generalDiagnostics"] if d["severity"] == "error"]
    assert bad.returncode != 0
    assert any(d.get("rule") == "reportAssignmentType" for d in errors)


def test_bitarray_generator_stays_bounded_and_copy_keeps_bits():
    bits = TvmBitarray()
    bits.extend(iter([1, 0, 1]))
    copied = bits.copy()
    assert copied.to01() == "101" and copied is not bits
    copied.append(0)
    assert bits.to01() == "101"
    with pytest.raises(TvmBitarrayOverflowException, match="overflow"):
        TvmBitarray().extend(iter([1] * 1024))


@pytest.mark.parametrize(
    "value, expected", [("0", 0), ("1", -1), ("01111111", 127), ("10000000", -128)]
)
def test_signed_bits_without_optional_dependencies(value, expected):
    assert bin_to_signed_int(value) == expected


def test_empty_schema_is_representable_and_unknown_schema_is_refused():
    assert TlSchema.empty().is_empty()
    schemas = TlGenerator.with_default_schemas().generate()
    with pytest.raises(TlError, match="unknown schema"):
        schemas.serialize("not_a_registered_schema", {})
    with pytest.raises(TlError, match="schema arguments"):
        schemas.deserialize(b"", boxed=False)


def test_required_field_and_address_kind_fail_before_serialization():
    with pytest.raises(TlbError, match="absent"):
        require(None)
    address = Address((0, bytes([7]) * 32))
    internal = Builder().store_address(address).end_cell().begin_parse()
    assert internal.load_internal_address() == address
    external = Builder().store_address(ExternalAddress(3, 2)).end_cell().begin_parse()
    with pytest.raises(SliceError, match="internal"):
        external.load_internal_address()
    internal = Builder().store_address(address).end_cell().begin_parse()
    with pytest.raises(SliceError, match="external"):
        internal.load_external_address()


def test_full_block_identity_hash_and_foreign_equality():
    first = BlockIdExt(-1, None, 3, bytes([1]) * 32, bytes([2]) * 32)
    same = BlockIdExt.from_dict(first.to_dict())
    other = BlockIdExt(0, None, 3, first.root_hash, first.file_hash)
    assert first == same and hash(first) == hash(same)
    assert len({first, same, other}) == 2
    assert first != object() and Cell.empty() != object()


def test_crypto_uses_installed_dependencies_and_private_operation_is_explicit():
    alice, bob = PrivateKey(bytes([1]) * 32), PrivateKey(bytes([2]) * 32)
    shared = get_shared_key(bytes(alice), bytes(bob.public_key))
    assert len(shared) == 32
    assert shared == get_shared_key(bytes(bob), bytes(alice.public_key))
    client = Client(bytes([3]) * 32)
    server = Server("127.0.0.1", 1, client.ed25519_public.encode())
    assert client.get_key_id() == server.get_key_id()
    with pytest.raises(ValueError, match="private key"):
        server.get_aes_key_id()


def test_wallet_signer_converts_wire_cell_without_a_null_provider(monkeypatch, wire_codec):
    transport = LiteClientTransport(Path("unused-client"), Path("unused-config"))
    key = SigningKey(bytes([4]) * 32)
    state = WalletV5State(True, 9, 11, key.verify_key.encode())
    monkeypatch.setattr(transport, "global_id", lambda: 42)
    wire_data = getattr(wire_codec, "from_boc")(state.serialize().to_boc())
    monkeypatch.setattr(transport, "account_data", lambda address: wire_data)
    signer = WalletV5Signer(transport, Address((0, bytes([5]) * 32)), key)
    assert signer.read_seqno() == 9
    assert asyncio.run(signer._view.current) == state


def test_account_data_preserves_wire_cell_auth_and_module_key(monkeypatch, wire_codec):
    transport = LiteClientTransport(Path("unused-client"), Path("unused-config"))
    wallet = Address((0, bytes([6]) * 32))
    module = Address((0, bytes([7]) * 32))
    auth = AuthState(2, 7, 8, bytes([9]) * 32)
    state = WalletV5State(True, 9, 11, bytes([4]) * 32, auth=auth)
    public_key = bytes([3]) * 1312
    module_data = Builder().store_int(42, 32).store_ref(byte_chain(public_key)).end_cell()
    blobs = {
        wallet.to_str(False): state.serialize().to_boc(),
        module.to_str(False): module_data.to_boc(),
    }
    saved_paths = []

    def save_data(command: str) -> str:
        verb, filename, address = shlex.split(command)
        assert verb == "saveaccountdata"
        path = Path(filename)
        saved_paths.append(path)
        path.write_bytes(blobs[address])
        return ""

    monkeypatch.setattr(transport, "_run", save_data)
    data = transport.account_data(wallet)
    assert isinstance(data, getattr(wire_codec, "Cell"))
    assert Cell.one_from_boc(data.boc()).hash == state.serialize().hash
    assert transport.read_auth(wallet) == auth
    assert transport.read_module_key(module) == public_key
    assert all(not path.exists() for path in saved_paths)
