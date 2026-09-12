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
    sign_body: object      # callable(body_cell, seqno, valid_until) -> Cell
    read_seqno: object     # callable() -> int


class LiteClientTransport:
    def __init__(self, binary: Path, config: Path, wallet: WalletSigner,
                 timeout: int = 25, poll_seconds: float = 2.0, attempts: int = 40):
        self.binary, self.config, self.wallet = Path(binary), Path(config), wallet
        self.timeout, self.poll_seconds, self.attempts = timeout, poll_seconds, attempts

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
        """Price from the chain being addressed, not from a constant."""
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
        """Price the two hops from this chain's own gas configuration."""
        prices = self.gas_prices(module.wc)
        # The module's flat post-quantum tariff dominates; the account's own
        # execution and the forwarding fee are added from the same prices.
        module_gas, account_gas, forward_gas = 64_400, 20_000, 10_000
        unit = prices['gas_price'] / (1 << 16)
        module_compute = max(1, int(module_gas * unit))
        account_execution = max(1, int(account_gas * unit))
        forwarding = max(1, int(forward_gas * unit))
        margin = max(1, (module_compute + account_execution + forwarding) // 10)
        total = module_compute + forwarding + account_execution + margin
        # The cap here is the transport's own quote ceiling; the relayer holds
        # the owner's cap separately and checks this against it.
        return FundingBudget(module_compute, forwarding, account_execution, margin, total)

    async def submit_internal(self, module: Address, body: Cell, value: int) -> str:
        """Send a funded internal message from the relayer wallet, or fail loudly."""
        available = self.balance(self.wallet.address)
        if available <= value:
            raise LiteClientError(
                f'relayer wallet holds {available} and cannot fund {value}; '
                'nothing was broadcast')
        seqno = self.wallet.read_seqno()
        _, chain_time = self.head()
        external = self.wallet.sign_body(module, body, value, seqno, chain_time + 600)
        boc = Path(f'/tmp/tos-pq-submit-{seqno}.boc')
        boc.write_bytes(external.to_boc() if hasattr(external, 'to_boc') else external.boc())
        try:
            self._run(f'sendfile {boc}')
        finally:
            boc.unlink(missing_ok=True)
        for _ in range(self.attempts):
            time.sleep(self.poll_seconds)
            if self.wallet.read_seqno() != seqno:
                return f'{self.wallet.address.to_str(False)}:{seqno}'
        raise LiteClientError('the wallet never advanced; the broadcast is unconfirmed')

    async def receipt(self, broadcast_id: str, request: AuthRequest,
                      module: Address) -> AttemptReceipt:
        module_exit, module_tx = self.last_transaction(module)
        account_exit, account_tx = self.last_transaction(request.account)
        module_success = None if module_tx is None else module_exit == 0
        account_success = None if account_tx is None else account_exit == 0
        # A refusal the account committed consumed the nonce; one it rejected
        # outright did not. Only the account can answer that.
        consumed = None
        if account_tx is not None:
            consumed = account_success or account_exit in (1713,)
        return AttemptReceipt(request.commitment.hex(), module, request.account,
                              module_success, account_success, consumed,
                              module_tx, account_tx)
