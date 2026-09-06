import asyncio
from contextlib import ExitStack
import functools
import logging
import os
import shlex
import signal
import subprocess
import types
from abc import ABC, abstractmethod
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from enum import IntEnum, auto
from ipaddress import IPv4Address
from pathlib import Path
from typing import Literal, final, override

from tosapi import tos_api

from tl import TLObject
from toslib import EngineConsoleClient, ToslibClient, ToslibError, ToslibEventLoop

from .install import Install
from .key import Key
from .log_streamer import LogStreamer
from .zerostate import NetworkConfig, Zerostate, create_zerostate

l = logging.getLogger(__name__)


@dataclass
class _IPv4AddressAndPort:
    ip: IPv4Address
    port: int

    @property
    def address(self):
        return f"{str(self.ip)}:{self.port}"


class _Status(IntEnum):
    INITED = auto()
    ZEROSTATE_GENERATED = auto()
    CLOSED = auto()


def _write_model(file: Path, model: TLObject):
    _ = file.write_text(model.to_json())


type DebugType = None | Literal["rr", "strace"]


@dataclass(frozen=True)
class StartOptions:
    install: Install | None = None
    debug: DebugType = None
    env: Mapping[str, str] = types.MappingProxyType({})
    args: Sequence[str] = ()
    threads: int = 0
    verbosity: int = 3
    stderr_to_file: bool = False


def _get_install_and_options(
    options: StartOptions | None, install: Install, additional_args: list[str]
) -> tuple[StartOptions, Install]:
    if options is None:
        options = StartOptions()

    if options.install is not None:
        install = options.install

    return (
        replace(options,
            install=install,
            args=additional_args + list(options.args),
        ),
        install,
    )


@final
class Network:
    class Node(ABC):
        def __init__(
            self,
            network: "Network",
            name: str,
        ):
            self._network: Network = network
            self.name: str = name

            self._directory: Path = self._network._directory / (
                "node" + str(self._network._node_idx)
            )
            self._network._node_idx += 1

            self._keyring: Path = self._directory / "keyring"
            self._keyring.mkdir(parents=True)
            self._keyring.chmod(0o700)

            self._static_nodes: list["DHTNode"] = []

            self.__process: asyncio.subprocess.Process | None = None
            self.__process_watcher: asyncio.Task[None] | None = None
            self.__log_streamer: LogStreamer | None = None

        def _new_network_address(self) -> _IPv4AddressAndPort:
            self._network._port += 1
            return _IPv4AddressAndPort(
                IPv4Address("127.0.0.1"),
                self._network._port,
            )

        def _new_keyring_key(self) -> tuple[Key, Path]:
            key = Key()
            path = key.add_to_keyring(self._keyring)
            return key, path

        def _ensure_no_zerostate_yet(self):
            assert self._network._status < _Status.ZEROSTATE_GENERATED

        def _get_or_generate_zerostate(self):
            return self._network._get_or_generate_zerostate()

        @property
        def _toslib(self):
            return self._network._toslib

        @property
        def _toslib_event_loop(self):
            return self._network._event_loop

        @property
        def log_path(self):
            return self._directory / "log"

        @property
        def session_log_path(self):
            return self._directory / "session-logs"

        async def _run(
            self,
            executable: Path,
            local_config: tos_api.Engine_validator_config,
            validator_config: tos_api.Validator_config_global | None,
            start_options: StartOptions,
        ):
            async def process_watcher():
                assert self.__process is not None
                return_code = await self.__process.wait()
                if return_code < 0:
                    signal_name = signal.Signals(-return_code).name
                    l.info(f"Node '{self.name}' terminated by signal {signal_name}")
                else:
                    l.info(f"Node '{self.name}' exited with code {return_code}")

            assert self._network._status < _Status.CLOSED

            global_config_file = self._directory / "config.global.json"
            _write_model(
                global_config_file,
                tos_api.Config_global(
                    dht=tos_api.Dht_config_global(
                        static_nodes=tos_api.Dht_nodes(
                            nodes=[node.signed_address for node in self._static_nodes]
                        ),
                        k=3,
                        a=3,
                    ),
                    validator=validator_config,
                ),
            )

            local_config_file = self._directory / "config.json"
            _write_model(local_config_file, local_config)

            l.info(f"Running {self.name} and saving its raw log to {self.log_path}")

            cmd_flags = [
                "--global-config",
                global_config_file,
                "--local-config",
                local_config_file,
                "--db",
                ".",
                "-v" + str(start_options.verbosity),
            ]
            if start_options.threads != 0:
                cmd_flags += ["--threads", str(start_options.threads)]
            cmd_flags += list(start_options.args)

            process_env = os.environ.copy()
            process_env.update(start_options.env)

            command = [executable, *cmd_flags]
            if start_options.debug == "rr":
                l.info(f"Recording {self.name} with rr")
                command = ["rr", "record", *command]
            elif start_options.debug == "strace":
                # Detached tracer preserves the child's PID for supervision
                # and memory observations. Do not record buffer contents.
                command = ["strace", "-D", "-f", "-ttt", "-T", "-s", "0", "-yy",
                           "-e", "trace=read,write,pread64,pwrite64,fsync,fdatasync,futex,clock_nanosleep,sched_yield",
                           "-o", self._directory / "syscalls.log", *command]
            elif start_options.debug is not None:
                raise ValueError(f"unsupported debugger: {start_options.debug}")
            with ExitStack() as files:
                # Direct logs must not depend on the controller event loop
                # draining a pipe while it decodes large state responses.
                stderr = files.enter_context(open(self.log_path, "wb", buffering=0)) if start_options.stderr_to_file else asyncio.subprocess.PIPE
                self.__process = await asyncio.create_subprocess_exec(
                    *command, cwd=self._directory, env=process_env, stderr=stderr)
            self.__process_watcher = asyncio.create_task(process_watcher())
            if not start_options.stderr_to_file:
                assert self.__process.stderr is not None
                self.__log_streamer = LogStreamer(
                    open(self.log_path, "wb", buffering=0), self.name, self.__process.stderr)

        def announce_to(self, dht: "DHTNode"):
            self._static_nodes.append(dht)

        @property
        def process_id(self) -> int | None:
            if self.__process is None or self.__process.returncode is not None:
                return None
            return self.__process.pid

        @abstractmethod
        async def run(self, options: StartOptions | None = None):
            pass

        async def stop(self):
            if self.__process:
                assert self.__process_watcher is not None

                if not self.__process_watcher.done():
                    l.info(f"Killing node '{self.name}'")
                    try:
                        self.__process.terminate()
                    except ProcessLookupError:
                        # Terminate might still fail if Python internally has already finished
                        # waiting for the child process but didn't yet resume the watcher.
                        pass

                await self.__process_watcher
                if self.__log_streamer is not None:
                    await self.__log_streamer.aclose()

                self.__process = None
                self.__process_watcher = None
                self.__log_streamer = None

    def __init__(
        self,
        install: Install,
        directory: Path,
        event_loop: asyncio.AbstractEventLoop | None = None,
        *,
        base_port: int = 2000,
    ):
        self._install = install
        self._directory = directory.absolute()
        self._port = base_port
        self._node_idx = 0
        self._status = _Status.INITED

        self._toslib = install.toslibjson
        self._event_loop = ToslibEventLoop(self._toslib, event_loop)

        self.__nodes: list[Network.Node] = []
        self.__full_nodes: list[FullNode] = []
        self.__network_config: NetworkConfig = NetworkConfig()
        self.__zerostate: Zerostate | None = None

    @property
    def zerostate(self) -> Zerostate:
        assert self.__zerostate is not None
        return self.__zerostate

    @property
    def config(self):
        assert self._status < _Status.ZEROSTATE_GENERATED
        return self.__network_config

    @property
    def install(self):
        return self._install

    def create_dht_node(self) -> "DHTNode":
        assert self._status < _Status.CLOSED

        node = DHTNode(self, f"dht-{len(self.__nodes)}")
        self.__nodes.append(node)
        return node

    def create_full_node(self) -> "FullNode":
        assert self._status < _Status.CLOSED

        node = FullNode(self, f"node-{len(self.__nodes)}")
        self.__nodes.append(node)
        self.__full_nodes.append(node)
        return node

    def _get_or_generate_zerostate(self) -> Zerostate:
        if self.__zerostate is not None:
            return self.__zerostate

        assert self._status == _Status.INITED

        state_dir = self._directory / "state"
        state_dir.mkdir()

        self.__zerostate = create_zerostate(
            self._install,
            state_dir,
            self.__network_config,
            [node.validator_key for node in self.__full_nodes if node.is_initial_validator],
        )
        self._status = _Status.ZEROSTATE_GENERATED
        return self.__zerostate

    async def aclose(self):
        assert self._status < _Status.CLOSED
        self._status = _Status.CLOSED

        for node in self.__nodes:
            await node.stop()

        self._event_loop.close()

    async def __aenter__(self):
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: types.TracebackType | None,
    ) -> bool | None:
        await asyncio.shield(self.aclose())

    async def wait_mc_block(self, seqno: int):
        client = await self.__full_nodes[0].toslib_client()

        while True:
            try:
                mc_info = await client.get_masterchain_info()
            except ToslibError as e:
                # FIXME: We should really let node notify us that it is ready.
                try:
                    if (
                        e.result.code == 500
                        and (
                            e.result.message
                            == "LITE_SERVER_NETWORKtimeout for adnl query query"  # node is not synced yet
                            or e.result.message
                            == "LITE_SERVER_NETWORK"  # node is not listening the socket
                        )
                    ):
                        await asyncio.sleep(0.2)
                        continue
                except Exception:
                    pass
                raise

            assert mc_info.last is not None

            if mc_info.last.seqno >= seqno:
                break
            else:
                await asyncio.sleep(0.2)

    async def wait_block(self, workchain: int, shard: int, seqno: int):
        client = await self.__full_nodes[0].toslib_client()

        while True:
            try:
                return await client.lookup_block(workchain=workchain, shard=shard, seqno=seqno)
            except ToslibError as e:
                try:
                    if e.result.code == 500 and (
                        "LITE_SERVER_UNKNOWN:" in e.result.message
                        or "LITE_SERVER_NOTREADY:" in e.result.message
                    ):
                        await asyncio.sleep(0.2)
                        continue
                except Exception:
                    pass
                raise


def _ip_to_tl(ip: IPv4Address) -> int:
    result = int(ip)
    if result >= 2**31:
        result -= 2**32
    return result


@final
class DHTNode(Network.Node):
    def __init__(self, network: "Network", name: str):
        super().__init__(network, name)

        self._addr = self._new_network_address()

        key, pk_file = self._new_keyring_key()

        address_list_to_sign = tos_api.Adnl_addressList(
            addrs=[
                tos_api.Adnl_address_udp(ip=_ip_to_tl(self._addr.ip), port=self._addr.port),
            ]
        )
        signed_address = subprocess.run(
            (
                self._network.install.key_helper_exe,
                "-m",
                "dht",
                "-k",
                pk_file,
                "-a",
                address_list_to_sign.to_json(),
            ),
            check=True,
            stdout=subprocess.PIPE,
        ).stdout
        self._signed_address = tos_api.Dht_node.from_json(signed_address.decode())

        self._local_config = tos_api.Engine_validator_config(
            addrs=[
                tos_api.Engine_addr(
                    ip=_ip_to_tl(self._addr.ip),
                    port=self._addr.port,
                    categories=[0],
                )
            ],
            adnl=[tos_api.Engine_adnl(id=key.id, category=0)],
            dht=[tos_api.Engine_dht(id=key.id)],
        )

    @property
    def signed_address(self):
        return self._signed_address

    @override
    async def run(self, options: StartOptions | None = None):
        options, install = _get_install_and_options(options, self._network.install, [])
        await self._run(
            install.dht_server_exe,
            self._local_config,
            None,
            options,
        )


@final
class FullNode(Network.Node):
    def __init__(self, network: "Network", name: str):
        super().__init__(network, name)

        KEY_EXPIRATION = (1 << 31) - 1

        self._addr = self._new_network_address()
        self._liteserver_addr = self._new_network_address()
        self._engine_console_addr = self._new_network_address()

        self._fullnode_key, _ = self._new_keyring_key()
        self._validator_key, _ = self._new_keyring_key()
        self._liteserver_key, _ = self._new_keyring_key()
        self._engine_console_server_key, _ = self._new_keyring_key()
        self._engine_console_client_key = Key()

        self._local_config = tos_api.Engine_validator_config(
            addrs=[
                tos_api.Engine_addr(
                    ip=_ip_to_tl(self._addr.ip),
                    port=self._addr.port,
                    categories=[0],
                )
            ],
            adnl=[
                tos_api.Engine_adnl(id=self._fullnode_key.id, category=0),
                tos_api.Engine_adnl(id=self._validator_key.id, category=0),
            ],
            dht=[
                tos_api.Engine_dht(id=self._fullnode_key.id),
            ],
            validators=[
                tos_api.Engine_validator(
                    id=self._validator_key.id,
                    temp_keys=[
                        tos_api.Engine_validatorTempKey(
                            key=self._validator_key.id,
                            expire_at=KEY_EXPIRATION,
                        )
                    ],
                    adnl_addrs=[
                        tos_api.Engine_validatorAdnlAddress(
                            id=self._validator_key.id,
                            expire_at=KEY_EXPIRATION,
                        )
                    ],
                    expire_at=KEY_EXPIRATION,
                )
            ],
            fullnode=self._fullnode_key.id,
            liteservers=[
                tos_api.Engine_liteServer(
                    id=self._liteserver_key.id,
                    # FIXME: IP?
                    port=self._liteserver_addr.port,
                )
            ],
            control=[
                tos_api.Engine_controlInterface(
                    id=self._engine_console_server_key.id,
                    # FIXME: IP?
                    port=self._engine_console_addr.port,
                    allowed=[
                        tos_api.Engine_controlProcess(
                            id=self._engine_console_client_key.id,
                            permissions=15,
                        )
                    ],
                )
            ],
        )

        self._is_initial_validator = False

        self._client: ToslibClient | None = None
        self._engine_console: EngineConsoleClient | None = None
        self._blockchain_explorer: asyncio.Task[None] | None = None
        self._static_populated = False

    def make_initial_validator(self):
        self._ensure_no_zerostate_yet()
        self._is_initial_validator = True

    @property
    def is_initial_validator(self):
        return self._is_initial_validator

    @property
    def validator_key(self):
        return self._validator_key

    @override
    async def run(self, options: StartOptions | None = None, *, seed_extra_states: bool = True):
        """Start the node; seed_extra_states controls first-start static files only."""
        zerostate = self._get_or_generate_zerostate()

        if not self._static_populated:
            static_dir = self._directory / "static"
            static_dir.mkdir()
            # Cold-join tests can require extra workchains to obtain their
            # genesis state through peers, retaining only the trusted base.
            extra_states = zerostate.extra_shards if seed_extra_states else ()
            for state in (zerostate.masterchain, zerostate.shardchain, *extra_states):
                (static_dir / state.file_hash.hex().upper()).symlink_to(state.file)
            self._static_populated = True

        options, install = _get_install_and_options(
            options,
            self._network.install,
            [
                "--initial-sync-delay",
                "5",
                "--session-logs",
                str(self.session_log_path),
                "--quic-flood-control",
                "-1",
            ],
        )

        await self._run(
            install.validator_engine_exe,
            self._local_config,
            zerostate.as_validator_config(),
            options,
        )

    @property
    def _liteserver_config(self):
        return tos_api.Liteclient_config_global(
            liteservers=[
                tos_api.Liteserver_desc(
                    id=self._liteserver_key.public_key,
                    ip=_ip_to_tl(self._liteserver_addr.ip),
                    port=self._liteserver_addr.port,
                ),
            ],
            validator=self._get_or_generate_zerostate().as_validator_config(),
        )

    @property
    def liteserver_config(self):
        return self._liteserver_config

    async def toslib_client(self) -> ToslibClient:
        if self._client:
            return self._client

        self._client = ToslibClient(self._liteserver_config, self._toslib)
        await self._client.init()

        return self._client

    @property
    def engine_console(self) -> EngineConsoleClient:
        if self._engine_console is None:
            self._engine_console = EngineConsoleClient(
                self._toslib,
                self._toslib_event_loop,
                tos_api.EngineConsoleClient_config(
                    address=self._engine_console_addr.address,
                    server_public_key=self._engine_console_server_key.public_key,
                    client_private_key=self._engine_console_client_key.private_key,
                ),
            )
        return self._engine_console

    @functools.cached_property
    def engine_console_cmd(self) -> str:
        server_pub = self._directory / "engine_console_server.pub"
        _ = self._engine_console_server_key.write_pub_key_file(server_pub)
        client_pk = self._directory / "engine_console_client.key"
        _ = self._engine_console_client_key.write_pk_key_file(client_pk)

        return shlex.join(
            [
                str(self._network.install.validator_engine_console_exe),
                "-a",
                self._engine_console_addr.address,
                "-k",
                str(client_pk),
                "-p",
                str(server_pub),
            ]
        )

    def enable_blockchain_explorer(self):
        if self._blockchain_explorer is not None:
            return

        address = self._new_network_address()
        config_file = self._directory / "explorer_config.json"
        _write_model(config_file, self._liteserver_config)

        async def explorer():
            cmd = [
                str(self._network.install.blockchain_explorer_exe),
                "-C",
                str(config_file),
                # FIXME: IP?
                "-H",
                str(address.port),
            ]
            l.info(
                f"Running blockchain explorer using node '{self.name}' on http://{address.address}/last"
            )
            process = await asyncio.create_subprocess_exec(
                *cmd,
                cwd=self._directory,
            )
            try:
                _ = await process.wait()
            except asyncio.CancelledError:
                try:
                    process.terminate()
                except ProcessLookupError:
                    pass
                _ = await asyncio.shield(process.wait())
                raise

        self._blockchain_explorer = asyncio.create_task(explorer())

    @override
    async def stop(self):
        if self._client:
            await self._client.aclose()
            self._client = None
        if self._engine_console:
            self._engine_console.close()
        if self._blockchain_explorer:
            _ = self._blockchain_explorer.cancel()
            try:
                await self._blockchain_explorer
            except asyncio.CancelledError:
                pass
        await super().stop()
