import asyncio
import logging
import traceback
from typing import Callable, final

from pytosiq_core import Address, Cell, MessageAny
from tosapi import tos_api, toslib_api

from .toslib_cdll import ToslibCDLL
from .toslibjson import TosLib

logger = logging.getLogger(__name__)


@final
class ToslibStateReader:
    def __init__(self, client: "ToslibClient"):
        self._client = client
        self._cache: dict[tuple[int, int, int, Address], Cell] = {}

    async def _get_data(self, address: Address) -> Cell:
        state = await self._client.raw_get_account_state(address)
        block_id = state.block_id
        assert block_id is not None
        key = (block_id.workchain, block_id.shard, block_id.seqno, address)
        if key not in self._cache:
            self._cache[key] = Cell.one_from_boc(state.data)
        return self._cache[key]

    async def fetch[T](self, address: Address, parser: Callable[[Cell], T]) -> T:
        data = await self._get_data(address)
        return parser(data)


class ToslibClient:
    def __init__(
        self,
        config: tos_api.Liteclient_config_global,
        toslib: ToslibCDLL,
        loop: asyncio.AbstractEventLoop | None = None,
    ):
        self._config: tos_api.Liteclient_config_global = config
        self._toslib: ToslibCDLL = toslib
        self._loop: asyncio.AbstractEventLoop | None = loop
        self._toslib_wrapper: TosLib | None = None

    async def init(self) -> None:
        if self._toslib_wrapper:
            logger.warning("init is already done")
            return
        event_loop = self._loop or asyncio.get_running_loop()
        self._toslib_wrapper = TosLib(event_loop, self._toslib)

        request = toslib_api.InitRequest(
            options=toslib_api.Options(
                config=toslib_api.Config(
                    config=self._config.to_json(),
                    blockchain_name="",
                    use_callbacks_for_network=False,
                    ignore_cache=False,
                ),
                keystore_type=toslib_api.KeyStoreTypeInMemory(),
            )
        )

        _ = await self._toslib_wrapper.execute(request)

    async def aclose(self):
        if self._toslib_wrapper is not None:
            await self._toslib_wrapper.aclose()
            self._toslib_wrapper = None

    async def __aenter__(self):
        await self.init()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: traceback.TracebackException | None,
    ):
        await self.aclose()

    def __await__(self):
        return self.init().__await__()

    async def sync_toslib(self) -> toslib_api.Tos_blockIdExt:
        assert self._toslib_wrapper is not None
        request = toslib_api.SyncRequest()
        return request.parse_result(await self._toslib_wrapper.execute(request))

    async def get_masterchain_info(self) -> toslib_api.Blocks_masterchainInfo:
        assert self._toslib_wrapper is not None
        request = toslib_api.Blocks_getMasterchainInfoRequest()
        return request.parse_result(await self._toslib_wrapper.execute(request))

    @property
    def latest_state_reader(self) -> ToslibStateReader:
        return ToslibStateReader(self)

    async def send_external(self, message: MessageAny) -> None:
        _ = await self.raw_send_message(message.serialize().to_boc())

    async def raw_send_message(self, serialized_boc: bytes) -> toslib_api.TypeOk:
        assert self._toslib_wrapper is not None
        request = toslib_api.Raw_sendMessageRequest(body=serialized_boc)
        return request.parse_result(await self._toslib_wrapper.execute(request))

    async def get_libraries(self, library_list: list[bytes]) -> toslib_api.Smc_libraryResult:
        assert self._toslib_wrapper is not None
        request = toslib_api.Smc_getLibrariesRequest(library_list)
        return request.parse_result(await self._toslib_wrapper.execute(request))

    async def raw_get_transactions(
        self, account_address: Address, from_transaction_id: toslib_api.Internal_transactionId
    ) -> toslib_api.Raw_transactions:
        assert self._toslib_wrapper is not None
        request = toslib_api.Raw_getTransactionsRequest(
            account_address=toslib_api.AccountAddress(
                account_address.to_str(is_user_friendly=True)
            ),
            from_transaction_id=from_transaction_id,
        )
        return request.parse_result(await self._toslib_wrapper.execute(request))

    async def raw_get_account_state(
        self, account_address: Address
    ) -> toslib_api.Raw_fullAccountState:
        assert self._toslib_wrapper is not None
        request = toslib_api.Raw_getAccountStateRequest(
            account_address=toslib_api.AccountAddress(account_address.to_str(is_user_friendly=True))
        )
        return request.parse_result(await self._toslib_wrapper.execute(request))

    async def lookup_block(
        self,
        workchain: int,
        shard: int,
        seqno: int | None = None,
        lt: int | None = None,
        utime: int | None = None,
    ):
        assert self._toslib_wrapper is not None
        assert seqno is not None or lt is not None or utime is not None
        mode = 0
        if seqno is not None:
            mode += 1
        if lt is not None:
            mode += 2
        if utime is not None:
            mode += 4
        request = toslib_api.Blocks_lookupBlockRequest(
            mode=mode,
            id=toslib_api.Tos_blockId(
                workchain=workchain,
                shard=shard,
                seqno=seqno or 0,
            ),
            lt=lt or 0,
            utime=utime or 0,
        )
        return request.parse_result(await self._toslib_wrapper.execute(request))

    async def get_shards(self, block_id: toslib_api.Tos_blockIdExt) -> toslib_api.Blocks_shards:
        assert self._toslib_wrapper is not None
        request = toslib_api.Blocks_getShardsRequest(id=block_id)
        return request.parse_result(await self._toslib_wrapper.execute(request))

    async def get_block_header(
        self, block_id: toslib_api.Tos_blockIdExt
    ) -> toslib_api.Blocks_header:
        assert self._toslib_wrapper is not None
        request = toslib_api.Blocks_getBlockHeaderRequest(id=block_id)
        return request.parse_result(await self._toslib_wrapper.execute(request))

    async def raw_get_block_transactions(
        self,
        block_id: toslib_api.Tos_blockIdExt,
        count: int,
        after: toslib_api.Blocks_accountTransactionId | None = None,
    ) -> toslib_api.Blocks_transactions:
        assert self._toslib_wrapper is not None
        mode = 7
        if after is not None:
            mode += 128
        request = toslib_api.Blocks_getTransactionsRequest(
            id=block_id,
            mode=mode,
            count=count,
            after=after,
        )
        return request.parse_result(await self._toslib_wrapper.execute(request))

    async def get_block_transactions(
        self,
        block_id: toslib_api.Tos_blockIdExt,
    ) -> list[toslib_api.Blocks_shortTxId]:
        result: list[toslib_api.Blocks_shortTxId] = []
        after = None
        while True:
            batch = await self.raw_get_block_transactions(block_id, 256, after)
            result.extend(batch.transactions)
            if not batch.incomplete:
                break
            after = toslib_api.Blocks_accountTransactionId(
                account=batch.transactions[-1].account,
                lt=batch.transactions[-1].lt,
            )
        return result
