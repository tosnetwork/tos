#!/usr/bin/env python3
"""Full StageA frozen runtime closure contract, checked only inside a ticket."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import stat

BINARY_PATHS = ('crypto/create-state', 'crypto/pq/tos-pq-consensus-key',
                'utils/generate-random-id', 'lite-client/lite-client',
                'validator-engine/validator-engine', 'dht-server/dht-server',
                'validator-engine-console/validator-engine-console',
                'blockchain-explorer/blockchain-explorer', 'crypto/func', 'crypto/fift',
                'toslib/libtoslibjson.so', 'tosctl/pq_pool_stake_order')


def require(value, reason):
    if not value:
        raise ValueError(reason)


def verify_binding(binding, host=False):
    require(binding['schema'] == 'tos.x02.four-node-binding.v1', 'binding schema differs')
    require(re.fullmatch('[0-9a-f]{40}', binding['native_source_sha']) is not None,
            'native source provenance absent')
    require(binding['stage_argv'] == [
        '--mode', 'experiment', '--stage', 'a', '--build-dir', binding['build_root'],
        '--base-port', '32600', '--rpc-base-port', '34600', '--duration-seconds', '420',
        '--settlement-tail-seconds', '600', '--sample-interval', '5',
        '--output-root', binding['stage_output'],
        '--pq-pool-stake-order-binary', str(Path(binding['build_root']) / 'tosctl/pq_pool_stake_order')],
        'full StageA argv differs from fixed preset')
    require(binding['python_version'][:2] >= [3, 14], 'StageA requires Python at least3.14')
    require(Path(binding['interpreter']).is_absolute()
            and Path(binding['build_root']).is_absolute()
            and Path(binding['source_root']).is_absolute(), 'binding path is not absolute')
    require(binding['rootfs_root'] == '/datax/n6-unit-agents/Z02/u24-rootfs'
            and binding['git_common_root'] == '/home/tomi/tos/.git'
            and binding['bwrap_path'] == '/usr/bin/bwrap', 'sandbox paths differ from fixed interface')
    require(binding['native_source_sha'] == 'f1f912dafd2dc3120e92829ec1858941bc426ec9'
            and binding['native_binary_sha256'] ==
                'e7670133c59160614fdedb04dd8ae03ba4be74c2a4841518f3ccec92cde4f3ee',
            'native snapshot differs from actual frozen f1f source/binary')
    if host:
        receipt = binding['host_files'][binding['bwrap_path']]
        require(hashlib.sha256(Path(binding['bwrap_path']).read_bytes()).hexdigest() == receipt['sha256'],
                'ordinary mount sandbox executable differs')
    os_release = Path(binding['rootfs_root']) / 'etc/os-release'
    require('VERSION_ID="24.04"' in os_release.read_text(), 'StageA rootfs is not U24')
    files = binding['files']
    require(isinstance(files, dict) and 0 < len(files) <= 100000, 'missing/boundless file closure')
    for relative in BINARY_PATHS:
        require(str(Path(binding['build_root']) / relative) in files,
                'missing StageA binary ' + relative)
    require(binding['interpreter'] in files, 'interpreter bytes not indexed')
    for relative in ('scripts/validator-election-stage-a.py', 'scripts/x02_stage_a_child.py',
                     'scripts/x02_four_node_binding.py', 'scripts/x01_window_evidence.py'):
        require(str(Path(binding['source_root']) / relative) in files,
                'StageA source/bootstrap bytes not indexed')
    require(binding['interpreter_stdlib_root'] in binding['runtime_roots'],
            'interpreter standard library closure absent')
    roots = [Path(binding['source_root']) / 'test/tostester/src',
             Path(binding['source_root']) / 'crypto/fift/lib',
             Path(binding['source_root']) / 'crypto/smartcont',
             Path(binding['build_root']) / 'crypto/smartcont',
             *map(Path, binding['dependency_roots']), *map(Path, binding['runtime_roots'])]
    require(len(binding['dependency_roots']) > 0, 'StageA dependency closure absent')
    for root in roots:
        require(root.is_dir(), 'runtime source/package/generated directory absent')
        actual = {str(path) for path in root.rglob('*') if path.is_file()}
        expected = {name for name in files if Path(name).is_relative_to(root)}
        require(actual == expected, 'unindexed or absent runtime file')
    for name, receipt in files.items():
        path = Path(name)
        require(path.is_absolute() and re.fullmatch('[0-9a-f]{64}', receipt['sha256']) is not None,
                'invalid frozen file binding')
        info = path.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_size == receipt['bytes'],
                'frozen runtime path/type/size changed')
        digest = hashlib.sha256()
        with path.open('rb') as stream:
            while chunk := stream.read(1024 * 1024):
                digest.update(chunk)
        require(digest.hexdigest() == receipt['sha256'], 'frozen runtime SHA differs: ' + name)
    require(binding['native_binary_sha256'] == files[
        str(Path(binding['build_root']) / 'validator-engine/validator-engine')]['sha256'],
        'native validator binding differs')
    return binding
