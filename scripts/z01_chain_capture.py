"""Retain raw PQ chain originals and replay to the Config30 exact target ID.

A development zerostate supplies a development anchor only. This module does
not authenticate an owner's final signature or infer signer authority.
"""

from pathlib import Path
import hashlib
import json
import re
import subprocess
import time
from typing import Any, Sequence

from scripts import z01_lite_quartet as lite


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def capture(lite_client: Path, checker: Path, lite_config: Path,
            anchor_root: str, anchor_file: str, zerostate: Path,
            target: Sequence[Any], block_boc: Path, out: Path,
            checker_sha256: str) -> dict[str, Any]:
    # Replay changes cwd to its own evidence directory. Preserve the caller's
    # path meanings before that change, including relative invocation paths.
    lite_client, checker, lite_config, zerostate, block_boc, out = (
        path.resolve() for path in (lite_client, checker, lite_config, zerostate, block_boc, out))
    target_text = lite.block_id_text(target)
    require(re.fullmatch('[0-9a-f]{64}', checker_sha256) is not None,
            'chain checker precommit binding is missing')
    require(all(isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value)
                and int(value, 16) for value in (anchor_root, anchor_file)),
            'invalid committed development anchor')
    require(hashlib.sha256(zerostate.read_bytes()).hexdigest() == anchor_file,
            'development zerostate file hash differs from committed anchor')
    require(hashlib.sha256(block_boc.read_bytes()).hexdigest() == target[4],
            'chain target block differs from Config30 fullID file hash')
    out.mkdir(exist_ok=False)
    out.chmod(0o700)
    prefix = out.resolve() / 'chain'
    require(not any(character.isspace() for character in str(prefix)),
            'chain capture prefix cannot contain parser whitespace')
    anchor_text = f'(-1,8000000000000000,0):{anchor_root.upper()}:{anchor_file.upper()}'
    command = f'saveblkproofchain {prefix} {anchor_text} {target_text}'
    original = lite.run_lite(lite_client, lite_config, [command], out, 'chain-query', timeout=60)
    require(original['exit'] == 0, 'chain query did not exit naturally0')
    marker = prefix.with_suffix('.complete')
    require(marker.is_file() and not marker.is_symlink() and 0 < marker.stat().st_size <= 1024,
            'chain query has no new complete marker')
    completed = re.fullmatch(rb'Z01_CHAIN_CAPTURE_OK segments=([0-9]+) target=([^\n]+)\n',
                             marker.read_bytes())
    require(completed is not None, 'chain completion marker is malformed')
    count = int(completed[1])
    require(1 <= count <= 32, 'chain completion segment count outside1..32')
    require(completed[2].decode('ascii').lower() == target_text.lower(),
            'chain completion marker differs from Config30 exact target')
    expected_names = {f'chain-{index}.{kind}.tl' for index in range(count)
                      for kind in ('request', 'response')}
    actual_names = {path.name for path in out.glob('chain-*.tl')}
    require(actual_names == expected_names, 'raw chain segments differ from declared completion count')
    responses = []
    files = []
    for index in range(count):
        for kind in ('request', 'response'):
            path = out / f'chain-{index}.{kind}.tl'
            require(path.is_file() and not path.is_symlink() and 0 < path.stat().st_size <= 16 * 1024 * 1024,
                    f'chain original missing or oversized: {index}.{kind}')
            files.append({'path': str(path.resolve()),
                          'sha256': hashlib.sha256(path.read_bytes()).hexdigest()})
            if kind == 'response':
                responses.append(str(path.resolve()))
    argv = [str(checker), anchor_root, anchor_file, str(zerostate), str(target[2]),
            target[3], target[4], str(block_boc), *responses]
    (out / 'chain-replay.command.json').write_text(json.dumps({
        'argv': argv, 'cwd': str(out.resolve()), 'checker_sha256_from_precommit': checker_sha256,
        'started_wall_ns': time.time_ns(),
    }) + '\n')
    try:
        result = subprocess.run(argv, cwd=out, capture_output=True, check=False, timeout=120)
        code, stdout, stderr = result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired as error:
        code, stdout, stderr = None, error.stdout or b'', error.stderr or b''
    for suffix, raw in [('stdout.raw', stdout), ('stderr.raw', stderr),
                        ('exit.raw', f'{code}\n'.encode())]:
        (out / ('chain-replay.' + suffix)).write_bytes(raw)
    require(code == 0, 'independent PQ chain replay did not exit naturally0')
    verified = re.fullmatch(rb'Z01_CHAIN_PROOF_OK seqno=([0-9]+) root=([a-fA-F0-9]{64}) '
                            rb'file=([a-fA-F0-9]{64}) links=([0-9]+)\n', stdout)
    require(verified is not None and int(verified[1]) == target[2]
            and verified[2].decode().lower() == target[3]
            and verified[3].decode().lower() == target[4] and int(verified[4]) > 0,
            'independent chain replay did not bind exact Config30 target')
    receipt = {'scope': 'development-fixed', 'final_signed_genesis': False,
               'anchor': [anchor_root, anchor_file], 'target_fullID': list(target),
               'segments': count, 'raw_files': files, 'checker_argv': argv,
               'checker_sha256_from_precommit': checker_sha256,
               'exit': code, 'links': int(verified[4]), 'passed': True}
    (out / 'chain-receipt.json').write_text(json.dumps(receipt, sort_keys=True, indent=2) + '\n')
    return receipt
