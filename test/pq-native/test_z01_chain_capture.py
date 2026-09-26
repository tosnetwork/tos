"""Fake transport/replay controls; no native chain or validator proof claim."""

import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from scripts import z01_chain_capture as chain


class ChainCaptureBoundary(unittest.TestCase):
    def exercise(self, directory, *, marker=True, wrong_target=False, replay_exit=0):
        zero = directory / 'zerostate.boc'
        block = directory / 'block.boc'
        zero.write_bytes(b'fake-zero')
        block.write_bytes(b'fake-target')
        anchor_file = hashlib.sha256(zero.read_bytes()).hexdigest()
        target = [-1, -(1 << 63), 12, '22' * 32, hashlib.sha256(block.read_bytes()).hexdigest()]
        out = directory / 'capture'

        def fake_transport(exe, config, commands, raw_out, label, **kwargs):
            target_text = chain.lite.block_id_text(target)
            if wrong_target:
                target_text = target_text.replace(',12)', ',13)')
            if marker:
                (out / 'chain.complete').write_text('Z01_CHAIN_CAPTURE_OK segments=1 target=' + target_text + '\n')
            for kind in ('request', 'response'):
                (out / f'chain-0.{kind}.tl').write_bytes(b'fake-raw-' + kind.encode())
            return {'exit': 0}

        def fake_replay(argv, **kwargs):
            for index in (0, 3, 7):
                self.assertTrue(Path(argv[index]).is_absolute())
            self.assertTrue(kwargs['cwd'].is_absolute())
            stdout = (f'Z01_CHAIN_PROOF_OK seqno=12 root={target[3]} file={target[4]} links=1\n').encode()
            return subprocess.CompletedProcess(argv, replay_exit, stdout, b'fake-native-rejection' if replay_exit else b'')

        with patch.object(chain.lite, 'run_lite', fake_transport), patch.object(chain.subprocess, 'run', fake_replay):
            return chain.capture(Path('/fake/lite'), Path('/fake/checker'), Path('/fake/config'),
                                 '11' * 32, anchor_file, zero, target, block, out, '33' * 32)

    def test_fake_positive_binds_same_target_and_is_development_only(self):
        with tempfile.TemporaryDirectory() as temp:
            result = self.exercise(Path(temp))
            self.assertEqual(result['target_fullID'][2], 12)
            self.assertEqual(result['segments'], 1)
            self.assertFalse(result['final_signed_genesis'])
            self.assertEqual(len(result['raw_files']), 2)
            self.assertTrue(result['passed'])

    def test_exit_zero_without_complete_marker_refused(self):
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaisesRegex(ValueError, 'no new complete marker'):
                self.exercise(Path(temp), marker=False)

    def test_relative_original_paths_preserve_meaning_at_replay_cwd(self):
        with tempfile.TemporaryDirectory() as temp:
            result = self.exercise(Path(os.path.relpath(temp)))
            self.assertTrue(Path(result['checker_argv'][3]).is_absolute())
            self.assertTrue(Path(result['checker_argv'][7]).is_absolute())

    def test_valid_marker_for_other_target_refused(self):
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaisesRegex(ValueError, 'differs from Config30 exact target'):
                self.exercise(Path(temp), wrong_target=True)

    def test_native_rejection_keeps_original_exit_and_stderr(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            with self.assertRaisesRegex(ValueError, 'replay did not exit naturally0'):
                self.exercise(directory, replay_exit=1)
            self.assertEqual((directory / 'capture/chain-replay.exit.raw').read_text(), '1\n')
            self.assertEqual((directory / 'capture/chain-replay.stderr.raw').read_bytes(), b'fake-native-rejection')


if __name__ == '__main__':
    unittest.main()
