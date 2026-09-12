#!/usr/bin/env python3
"""A RelayTransport that talks to a running chain through lite-client.

This is not a production RPC client. It is the first implementation that reads
its environment from a chain instead of a constant, prices a submission from
that chain's configuration, and fails the way a relayer actually fails — when
the funding wallet cannot pay, nothing is broadcast and no receipt appears.

It exists so the relayer control flow is exercised against something that can
refuse it. Every key it uses is public test material.
"""
from dataclasses import dataclass
import re
import subprocess
import time
from pathlib import Path

from pytosiq_core import Address, Cell

from .pq_relayer import AttemptReceipt, ChainSnapshot, FundingBudget
from .pq_auth import AuthRequest, AuthState


class LiteClientError(RuntimeError):
    """The node could not answer, which is not the same as a negative answer."""


@dataclass(frozen=True)
class WalletSigner:
    """The funded account that pays for a submission, and how to authorize it."""
    address: Address
    # callable(destination, body, value, seqno, valid_until, state_init) -> Cell,
    # returning a complete external message ready to be broadcast.
    sign_body: object
    read_seqno: object     # callable() -> int


class LiteClientTransport:
    def __init__(self, binary: Path, config: Path, wallet: WalletSigner | None = None,
                 timeout: int = 25, poll_seconds: float = 2.0, attempts: int = 40):
        self.binary, self.config, self.wallet = Path(binary), Path(config), wallet
        self.timeout, self.poll_seconds, self.attempts = timeout, poll_seconds, attempts
        # Where the module and the account stood when an attempt was prepared.
        # Without these, an account's own deployment reads as this attempt's
        # execution, and a receipt reports a nonce consumed that never was.
        self._module_marks: dict[str, int | None] = {}
        self._account_marks: dict[str, int | None] = {}

    def attach_wallet(self, wallet: WalletSigner) -> 'LiteClientTransport':
        """A signer reads its own state through this transport, so the two are
        wired after construction rather than in a single constructor call."""
        self.wallet = wallet
        return self

    def _run(self, command: str) -> str:
        result = subprocess.run(
            [str(self.binary), '-C', str(self.config), '-r', '-v', '0',
             '-t', str(self.timeout), '-c', command],
            capture_output=True, text=True, timeout=self.timeout * 4)
        if result.returncode != 0:
            raise LiteClientError(f'{command}: {result.stderr.strip()[:200]}')
        return result.stdout

    # ---- reads -----------------------------------------------------------

    def global_id(self) -> int:
        match = re.search(r'global_id:(-?\d+)', self._run('getconfig 19'))
        if not match:
            raise LiteClientError('the chain did not report a global id')
        return int(match.group(1))

    def global_version(self) -> int:
        match = re.search(r'version:(\d+)', self._run('getconfig 8'))
        if not match:
            raise LiteClientError('the chain did not report a global version')
        return int(match.group(1))

    def head(self) -> tuple[str, int]:
        text = self._run('last')
        block = re.search(r'latest masterchain block known to server is (\S+)', text)
        created = re.search(r'created at (\d+)', text)
        if not block or not created:
            raise LiteClientError('the chain did not report an anchored head')
        return block.group(1), int(created.group(1))

    def balance(self, address: Address) -> int:
        for line in self._run(f'getaccount {address.to_str(False)}').splitlines():
            if 'account balance is' in line:
                return int(line.split('is')[1].strip().rstrip('ng'))
        return 0

    def _get_method(self, address: Address, method: str) -> str:
        return self._run(f'runmethod {address.to_str(False)} {method}')

    def gas_prices(self, workchain: int) -> dict:
        """Read compute-gas prices from the chain being addressed."""
        param = 20 if workchain == -1 else 21
        text = self._run(f'getconfig {param}')
        # 'flat_gas_price' also ends in 'gas_price'; anchor away from it or the
        # estimate comes out hundreds of times too low.
        match = re.search(r'(?<!flat_)gas_price:(\d+)', text)
        flat_limit = re.search(r'flat_gas_limit:(\d+)', text)
        flat_price = re.search(r'flat_gas_price:(\d+)', text)
        if not match or not flat_limit or not flat_price:
            raise LiteClientError(f'the chain did not report gas prices in ConfigParam {param}')
        return {'gas_price': int(match.group(1)), 'flat_gas_limit': int(flat_limit.group(1)),
                'flat_gas_price': int(flat_price.group(1))}

    def forward_prices(self, workchain: int) -> dict:
        """Read message-forwarding prices instead of approximating them as gas."""
        param = 24 if workchain == -1 else 25
        text = self._run(f'getconfig {param}')
        values = {}
        for name in ('lump_price', 'bit_price', 'cell_price'):
            match = re.search(rf'(?<![A-Za-z0-9_]){name}:(\d+)', text)
            if not match:
                raise LiteClientError(
                    f'the chain did not report {name} in ConfigParam {param}')
            values[name] = int(match.group(1))
        return values

    @staticmethod
    def _gas_fee(gas_used: int, prices: dict) -> int:
        """Mirror GETGASFEE / the production compute-phase flat-prefix formula."""
        if gas_used <= prices['flat_gas_limit']:
            return prices['flat_gas_price']
        variable = prices['gas_price'] * (gas_used - prices['flat_gas_limit'])
        return prices['flat_gas_price'] + (variable + (1 << 16) - 1) // (1 << 16)

    @staticmethod
    def _tree_size(root: Cell) -> tuple[int, int]:
        """Count referenced message cells/bits once, as forwarding fees do."""
        seen = set()
        cells = bits = 0

        def walk(cell: Cell):
            nonlocal cells, bits
            if cell.hash in seen:
                return
            seen.add(cell.hash)
            cells += 1
            bits += len(cell.bits)
            for ref in cell.refs:
                walk(ref)

        walk(root)
        return cells, bits

    @staticmethod
    def _forward_fee(cells: int, bits: int, prices: dict) -> int:
        variable = prices['bit_price'] * bits + prices['cell_price'] * cells
        return prices['lump_price'] + (variable + (1 << 16) - 1) // (1 << 16)

    def account_data(self, address: Address) -> Cell:
        """The account's data cell, read from the chain rather than reconstructed."""
        import tempfile
        from cells import from_boc
        with tempfile.NamedTemporaryFile(suffix='.boc', delete=False) as handle:
            path = Path(handle.name)
        try:
            self._run(f'saveaccountdata {path} {address.to_str(False)}')
            if not path.is_file() or path.stat().st_size == 0:
                raise LiteClientError(f'no account data for {address.to_str(False)}')
            return from_boc(path.read_bytes())
        finally:
            path.unlink(missing_ok=True)

    def read_auth(self, account: Address) -> AuthState:
        """The live epoch and nonce, which is what a stale request gets refused on."""
        data = self.account_data(account)
        if not data.refs:
            raise LiteClientError('the account carries no authentication root')
        auth = data.refs[-1].slice()
        return AuthState(auth.uint(2), auth.uint(64), auth.uint(64), auth.uint(256).to_bytes(32, 'big'))

    def read_module_key(self, module: Address) -> bytes:
        """The key the deployed module will verify against, not the one we hold."""
        data = self.account_data(module)
        if not data.refs:
            raise LiteClientError('the module carries no public key')
        raw, cell = bytearray(), data.refs[0]
        while True:
            bits = cell.bits
            raw.extend(int(bits, 2).to_bytes(len(bits) // 8, 'big') if bits else b'')
            if not cell.refs:
                break
            cell = cell.refs[0]
        return bytes(raw)

    def _last_lt(self, address: Address) -> int | None:
        reference = self.last_transaction(address)[1]
        return None if reference is None else int(reference.split(':')[0])

    @staticmethod
    def _after(mark: int | None, reference: str | None) -> bool:
        """A transaction at or before the mark was already there; it is not ours."""
        if reference is None:
            return False
        return mark is None or int(reference.split(':')[0]) > mark

    def last_transaction(self, address: Address) -> tuple[int | None, str | None]:
        text = self._run(f'getaccount {address.to_str(False)}')
        match = re.search(r'last transaction lt = (\d+) hash = ([A-F0-9]+)', text)
        if not match:
            return None, None
        lt, digest = match.group(1), match.group(2)
        dump = self._run(f'lasttransdump {address.to_str(False)} {lt} {digest} 1')
        exit_code = re.search(r'exit_code:(-?\d+)', dump)
        return (int(exit_code.group(1)) if exit_code else None), f'{lt}:{digest}'

    # ---- the transport contract -----------------------------------------

    async def snapshot(self, account: Address, module: Address) -> ChainSnapshot:
        block_id, chain_time = self.head()
        auth = self.read_auth(account)
        self._account_marks[account.to_str(False)] = self._last_lt(account)
        return ChainSnapshot(
            network=self.global_id(),
            version=self.global_version(),
            chain_time=chain_time,
            account=account,
            module=module,
            auth=auth,
            module_public_key=self.read_module_key(module),
            block_id=block_id,
        )

    async def estimate(self, request: AuthRequest, module: Address) -> FundingBudget:
        """Price both compute phases and the actual relay body from chain config."""
        gas = self.gas_prices(module.wc)
        forward = self.forward_prices(module.wc)
        # The verifier's execution is effectively fixed-size because the signed
        # message is the 32-byte commitment. Account execution varies less, and
        # the relayer margin remains explicit. Keep the measured conservative
        # gas envelopes here while deriving their monetary cost from Config20/21.
        module_gas, account_gas = 64_400, 20_000
        module_compute = max(1, self._gas_fee(module_gas, gas))
        account_execution = max(1, self._gas_fee(account_gas, gas))
        # The module forwards the AUTH envelope, not the 2420-byte proof. Quote
        # the larger hybrid envelope so a PQ-only caller is never underfunded by
        # this transport merely because its mode was not passed into estimate().
        envelope = request.envelope(bytes(64))
        cells, bits = self._tree_size(envelope)
        forwarding = max(1, self._forward_fee(cells, bits, forward))
        margin = max(1, (module_compute + account_execution + forwarding) // 10)
        total = module_compute + forwarding + account_execution + margin
        # The cap here is the transport's own quote ceiling; the relayer holds
        # the owner's cap separately and checks this against it.
        return FundingBudget(module_compute, forwarding, account_execution, margin, total)

    def broadcast_external(self, message) -> None:
        """Submit an already-signed external message.

        This bypasses the funding wallet entirely, so it can only reach an
        account that accepts external messages. A contract that refuses them —
        the authentication module refuses every one by design — has to be
        deployed by a funded internal message instead; see `deploy`.
        """
        raw = message.to_boc() if hasattr(message, 'to_boc') else message.boc()
        import tempfile
        # A predictable name in a shared directory is somebody else's file to
        # replace; the broadcast has to carry what this call actually signed.
        with tempfile.NamedTemporaryFile(suffix='.boc', delete=False) as handle:
            handle.write(raw)
            path = Path(handle.name)
        try:
            self._run(f'sendfile {path}')
        finally:
            path.unlink(missing_ok=True)

    async def submit_internal(self, module: Address, body: Cell, value: int,
                              state_init=None) -> str:
        """Send a funded internal message from the relayer wallet, or fail loudly."""
        if self.wallet is None:
            raise LiteClientError('no funding wallet is attached; nothing was broadcast')
        available = self.balance(self.wallet.address)
        if available <= value:
            raise LiteClientError(
                f'relayer wallet holds {available} and cannot fund {value}; '
                'nothing was broadcast')
        seqno = self.wallet.read_seqno()
        module_mark = self._last_lt(module)
        _, chain_time = self.head()
        external = self.wallet.sign_body(module, body, value, seqno,
                                         chain_time + 600, state_init)
        self.broadcast_external(external)
        for _ in range(self.attempts):
            time.sleep(self.poll_seconds)
            if self.wallet.read_seqno() != seqno:
                broadcast = f'{self.wallet.address.to_str(False)}:{seqno}'
                self._module_marks[broadcast] = module_mark
                return broadcast
        raise LiteClientError('the wallet never advanced; the broadcast is unconfirmed')

    async def deploy(self, blueprint, value: int) -> Address:
        """Fund a contract into existence and confirm what the chain now holds.

        Broadcasting is not deployment. This returns only once the account
        carries the very data cell the blueprint computed its address from; an
        account that exists with different data is a different contract.
        """
        if value <= 0:
            raise LiteClientError('deployment needs positive funding')
        expected = blueprint.state_init.data.hash
        await self.submit_internal(blueprint.address, Cell.empty(), value,
                                   state_init=blueprint.state_init)
        for _ in range(self.attempts):
            try:
                if self.account_data(blueprint.address).hash == expected:
                    return blueprint.address
            except LiteClientError:
                pass
            time.sleep(self.poll_seconds)
        raise LiteClientError(
            f'{blueprint.address.to_str(False)} never came up with the expected state')

    async def receipt(self, broadcast_id: str, request: AuthRequest,
                      module: Address) -> AttemptReceipt:
        module_exit, module_tx = self.last_transaction(module)
        account_exit, account_tx = self.last_transaction(request.account)
        # Both accounts existed before this attempt. Only a transaction after
        # the point where the attempt was prepared can belong to it.
        if not self._after(self._module_marks.get(broadcast_id), module_tx):
            module_exit, module_tx = None, None
        if not self._after(self._account_marks.get(request.account.to_str(False)), account_tx):
            account_exit, account_tx = None, None
        module_success = None if module_tx is None else module_exit == 0
        # The module forwards only when it accepted the proof, so an attempt it
        # refused cannot have reached the account at all; whatever the account
        # last did belongs to something else and says nothing about this nonce.
        if module_success is False:
            account_exit, account_tx = None, None
        account_success = None if account_tx is None else account_exit == 0
        # A refusal the account committed consumed the nonce; one it rejected
        # outright did not. Only the account can answer that.
        consumed = None
        if account_tx is not None:
            consumed = account_success or account_exit in (1713,)
        return AttemptReceipt(request.commitment.hex(), module, request.account,
                              module_success, account_success, consumed,
                              module_tx, account_tx)


class WalletV5Signer:
    """A real Wallet V5 paying for submissions on a live chain.

    Its seqno, wallet id and stored key all come from the account itself. A
    locally cached seqno is the classic way to sign a message the chain will
    silently drop, or to overwrite a transfer somebody else just made from the
    same wallet, so nothing here is remembered between calls.
    """

    def __init__(self, transport: LiteClientTransport, address: Address, key):
        from .wallet_v5 import WalletV5
        self.transport, self.address, self.key = transport, address, key
        self._view = WalletV5(None, address, transport.global_id(), key)

    def state(self):
        from pytosiq_core import Cell as SDKCell
        from .wallet_v5 import WalletV5State
        data = self.transport.account_data(self.address)
        return WalletV5State.parse(SDKCell.one_from_boc(data.boc()))

    def read_seqno(self) -> int:
        return self.state().seqno

    def sign_body(self, destination: Address, body: Cell, value: int, seqno: int,
                  valid_until: int, state_init=None):
        from pytosiq_core import ExternalMsgInfo, MessageAny
        state = self.state()
        # The caller read the seqno, then the chain had time to move. Signing
        # for a seqno the wallet has left behind produces a message that is
        # dropped without a trace, which reads exactly like a lost broadcast.
        if state.seqno != seqno:
            raise LiteClientError(
                f'wallet seqno moved from {seqno} to {state.seqno}; nothing was signed')
        payload = self._view.transfer_payload(destination, value, body, state_init)
        signed = self._view.sign(payload, state, valid_until)
        info = ExternalMsgInfo(None, self.address, 0)
        return MessageAny(info=info, init=None, body=signed).serialize()
