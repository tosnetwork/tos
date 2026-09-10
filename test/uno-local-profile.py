#!/usr/bin/env python3
"""Run the independent UNO local profile on real unmodified node binaries."""
import argparse
import asyncio
import hashlib
import json
from pathlib import Path
import sys

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / 'test/tostester/src'))
from pytosiq_core import Cell
from pytosiq_core.tlb.block import ShardStateUnsplit
from tostester.install import Install
from tostester.network import Network, StartOptions
from tosapi import tos_api
from toslib.toslibjson import ToslibError

p = argparse.ArgumentParser()
p.add_argument('--build', type=Path, required=True)
p.add_argument('--out', type=Path, required=True)
p.add_argument('--port', type=int, default=34000)
a = p.parse_args()
a.out.mkdir(parents=True, exist_ok=False)
report = {'scope': 'Independent local chain, no UNO engine registration; not account-batch execution acceptance.', 'global_id': 4, 'runs': []}
def save():
    (a.out / 'report.json').write_text(json.dumps(report, indent=2) + '\n')

async def main():
    install = Install(a.build, REPO)
    for path in (install.fift_exe, install.validator_engine_exe, install.dht_server_exe):
        report.setdefault('binaries', {})[str(path)] = hashlib.sha256(path.read_bytes()).hexdigest()
    async with Network(install, a.out, base_port=a.port) as network:
        network.config.uno_workchain = True
        network.config.global_id = 4
        network.config.global_version = 16
        network.config.shard_validators = 3
        dht = network.create_dht_node()
        nodes = [network.create_full_node() for _ in range(3)]
        for node in nodes:
            node.make_initial_validator()
            node.announce_to(dht)
            node._local_config.shards_to_monitor = [
                tos_api.TosNode_shardId(workchain=0, shard=-(1 << 63))]

        state = network._get_or_generate_zerostate()
        parsed = ShardStateUnsplit.deserialize(Cell.one_from_boc(state.masterchain.file.read_bytes()).begin_parse())
        assert parsed.custom.workchain_instances is not None, '1201: missing authenticated ledger'
        assert 84 in parsed.custom.config.config, '1202: missing ingress configuration'
        assert len(state.extra_shards) == 1, '1203: missing UNO shard zerostate'
        report['genesis'] = {'root_hash': state.masterchain.root_hash.hex(), 'file_hash': state.masterchain.file_hash.hex(),
                             'ledger_boc': parsed.custom.workchain_instances.to_boc().hex()}
        save()
        # This network carries wc=2 but has no engine that could serve it.
        # Do not request the default all-active-workchain local execution role.
        options = StartOptions(threads=4, stderr_to_file=True, verbosity=2,
                               args=['--not-all-shards'])
        await dht.run(StartOptions(threads=2, stderr_to_file=True, verbosity=2))
        await asyncio.gather(*(node.run(options) for node in nodes))
        await asyncio.wait_for(network.wait_mc_block(8), timeout=180)
        for node in nodes:
            client = await node.toslib_client()
            info = await client.get_masterchain_info()
            report['runs'].append({'phase': 'before_restart', 'node': node.name, 'seqno': info.last.seqno})
            assert info.last.seqno >= 1, '1204: node did not observe produced masterchain blocks'
        save()
        await nodes[2].stop()
        await nodes[2].run(options)
        target = max(row['seqno'] for row in report['runs']) + 8
        await asyncio.wait_for(network.wait_mc_block(target), timeout=120)
        async def observe_restarted_node():
            client = await nodes[2].toslib_client()
            while True:
                try:
                    info = await client.get_masterchain_info()
                    if info.last.seqno >= target:
                        return info
                except ToslibError as error:
                    if error.result.code != 500 or not error.result.message.startswith('LITE_SERVER_NETWORK'):
                        raise
                await asyncio.sleep(0.2)
        info = await asyncio.wait_for(observe_restarted_node(), timeout=90)
        report['runs'].append({'phase': 'after_restart', 'node': nodes[2].name, 'seqno': info.last.seqno})
        assert info.last.seqno >= target, '1205: restarted node failed to reload and progress'
        save()
try:
    asyncio.run(main())
except BaseException as error:
    report['error'] = repr(error)
    save()
    raise
print(f'PASS: UNO local chain and restart; evidence={a.out}')
