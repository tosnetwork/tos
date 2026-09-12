#!/usr/bin/env python3
"""Executed SDK-produced messages in the native transaction/action emulator.

Known fixture seed is public test data. No running network is contacted.
"""
import argparse
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
import subprocess

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT/'test/tostester/src'), str(ROOT/'test/mldsa-auth'), str(ROOT/'test/auth-extensions')]
from contract import (WalletV5Blueprint, WalletV5State, AgentAccountBlueprint,
                      AgentAccountState, AgentPolicy, AuthState, Mldsa44ModuleBlueprint, NativeMldsa44Signer)
from contract.pq_auth import AuthRequest
from pytosiq_core import Cell as SDKCell, Address
import nacl.signing
from build_contracts import build_contracts
from cells import Cell, from_boc
from native import Emulator, NOW, GLOBAL_ID, outgoing, account_data, internal, external
from protocol import emulator_library, parse_message


def source_commit() -> str:
    """Bind a report to the tree that produced it, for the activation precheck."""
    return subprocess.run(['git', 'rev-parse', 'HEAD'], cwd=ROOT, check=True,
                          capture_output=True, text=True).stdout.strip()

ARGS = None
RESULTS = []


def native(cell):
    return from_boc(cell.to_boc())


def sdk(cell):
    return SDKCell.one_from_boc(cell.boc())


def addr(value):
    return (value.wc, int.from_bytes(value.hash_part, 'big'))


def empty_account():
    return Cell().uint(0, 256).uint(0, 64).ref(Cell().uint(0, 1))


def success(result):
    assert result['success'], result
    details = result['details']
    assert details['exit'] == 0 and not details['aborted'], details
    assert details['action'] is None or details['action']['success'], details


def deploy(emulator, blueprint):
    sender = Address((blueprint.address.wc, (17).to_bytes(32, 'big')))
    message = native(blueprint.deployment_message(sender, 100_000_000_000).serialize())
    result = emulator.send(empty_account(), message)
    success(result)
    shard = from_boc(result['shard_account'])
    assert account_data(shard)[0].hash == blueprint.state_init.data.hash
    return shard


class SDKNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.key = Path(cls.tmp.name)/'PUBLIC-TEST-SEED'
        cls.key.write_bytes(bytes([0xa5])*32)
        cls.key.chmod(0o600)
        cls.signer = NativeMldsa44Signer(ARGS.key_tool, cls.key)
        cls.classic = nacl.signing.SigningKey(bytes([0x42])*32)
        cls.codes = {n: SDKCell.one_from_boc((ARGS.out/f'{n}.boc').read_bytes()) for n in (
            'wallet-func','wallet-tol','agent','module-func','module-tol')}

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def blueprint(self, impl, wc, auth=None):
        if impl == 'agent':
            return AgentAccountBlueprint(self.codes[impl], wc, GLOBAL_ID, Address((wc,(17).to_bytes(32,'big'))),
                self.classic.verify_key.encode(), (5).to_bytes(32,'big'), AgentPolicy(5_000_000_000,6_000_000_000), auth, self.classic)
        return WalletV5Blueprint(self.codes[impl], wc, GLOBAL_ID, self.classic.verify_key.encode(), auth=auth, key=self.classic)

    def test_real_funded_deployment_and_classic_transfer(self):
        for impl in ('wallet-func','wallet-tol','agent'):
            for wc in (0,-1):
                with self.subTest(impl=impl,wc=wc):
                    e=Emulator(16);self.addCleanup(e.close)
                    bp=self.blueprint(impl,wc);shard=deploy(e,bp);view=bp.materialize(None)
                    state=view._parse_state(sdk(account_data(shard)[0]))
                    target=Address((wc,(20).to_bytes(32,'big')))
                    if impl=='agent':
                        payload=view.transfer_payload(state,target,1_000_000_000,NOW+600);body=view.sign(payload,state)
                    else:
                        payload=view.transfer_payload(target,1_000_000_000);body=view.sign(payload,state,NOW+600)
                    result=e.send(shard,external(addr(bp.address),native(body)));success(result)
                    messages=outgoing(from_boc(result['transaction']))
                    self.assertEqual(len(messages),1)
                    transfer=parse_message(messages[0]);self.assertEqual(transfer['value'],1_000_000_000)
                    self.assertEqual(transfer['destination'],addr(target))
                    after=view._parse_state(sdk(account_data(from_boc(result['shard_account']))[0]))
                    self.assertEqual(after.seqno,1)
                    RESULTS.append({'kind':'classic','implementation':impl,'workchain':wc,'gas':result['details']['gas'],'outgoing_transfer':True})

    def test_real_pq_and_hybrid_deployment_transfer_replay_and_v15(self):
        for language in ('func','tol'):
            for impl in ('wallet-func','wallet-tol','agent'):
                for wc in (0,-1):
                    for mode in (2,3):
                        with self.subTest(language=language,impl=impl,wc=wc,mode=mode):
                            me=Emulator(16);ae=Emulator(16);self.addCleanup(me.close);self.addCleanup(ae.close)
                            mb=Mldsa44ModuleBlueprint(self.codes['module-'+language],wc,GLOBAL_ID,self.signer.public_key())
                            ms=deploy(me,mb)
                            bp=self.blueprint(impl,wc,AuthState(mode,1,0,mb.address.hash_part))
                            account=deploy(ae,bp);view=bp.materialize(None)
                            state=view._parse_state(sdk(account_data(account)[0]))
                            target=Address((wc,(20).to_bytes(32,'big')))
                            payload=(view.transfer_payload(state,target,1_000_000_000,NOW+600) if impl=='agent'
                                     else view.transfer_payload(target,1_000_000_000))
                            req=view.pq_request(state,payload,NOW+600)
                            co=self.classic.sign(req.commitment).signature if mode==3 else None
                            sig=self.signer.sign(req.commitment)
                            broken=bytearray(sig);broken[100]^=1
                            bad=me.send(ms,internal((wc,17),addr(mb.address),native(req.submission(bytes(broken),co)),10_000_000_000))
                            self.assertEqual(bad['details']['exit'],1808)
                            self.assertFalse(outgoing(from_boc(bad['transaction'])))
                            # Use the actual post-failure shard, not a magically restored balance.
                            ms=from_boc(bad['shard_account'])
                            body=native(req.submission(sig,co))
                            v15=Emulator(15);self.addCleanup(v15.close)
                            blocked=v15.send(ms,internal((wc,17),addr(mb.address),body,10_000_000_000))
                            self.assertEqual(blocked['details']['exit'],6)
                            result=me.send(ms,internal((wc,17),addr(mb.address),body,10_000_000_000));success(result)
                            relay=outgoing(from_boc(result['transaction']))[0]
                            ae.lt=max(ae.lt,parse_message(relay)['created_lt'])
                            ar=ae.send(account,relay);success(ar)
                            transfer=parse_message(outgoing(from_boc(ar['transaction']))[0])
                            self.assertEqual(transfer['destination'],addr(target));self.assertEqual(transfer['value'],1_000_000_000)
                            account=from_boc(ar['shard_account'])
                            after=view._parse_state(sdk(account_data(account)[0]));self.assertEqual(after.auth.nonce,1)
                            self.assertEqual(after.seqno,1)
                            ms=from_boc(result['shard_account'])
                            again=me.send(ms,internal((wc,17),addr(mb.address),body,10_000_000_000));success(again)
                            relay=outgoing(from_boc(again['transaction']))[0]
                            ae.lt=max(ae.lt,parse_message(relay)['created_lt'])
                            rejected=ae.send(account,relay);self.assertEqual(rejected['details']['exit'],1804)
                            self.assertEqual(account_data(from_boc(rejected['shard_account']))[0].hash,account_data(account)[0].hash)
                            RESULTS.append({'kind':'pq','language':language,'implementation':impl,'workchain':wc,'mode':mode,
                                'module_gas':result['details']['gas'],'account_gas':ar['details']['gas'],
                                'outgoing_transfer':True,'replay_exit':1804,'v15_exit':6,'bad_signature_exit':1808})

    def test_key_file_safety(self):
        with tempfile.TemporaryDirectory() as d:
            key=Path(d)/'key'
            cmd=[str(ARGS.key_tool)]
            self.assertEqual(subprocess.run(cmd+['keygen',str(key)],capture_output=True).returncode,0)
            self.assertEqual(key.stat().st_mode&0o777,0o600)
            self.assertNotEqual(subprocess.run(cmd+['keygen',str(key)],capture_output=True).returncode,0)
            link=Path(d)/'link';link.symlink_to(key)
            self.assertNotEqual(subprocess.run(cmd+['public',str(link)],capture_output=True).returncode,0)
            key.chmod(0o644)
            self.assertNotEqual(subprocess.run(cmd+['public',str(key)],capture_output=True).returncode,0)
            key.chmod(0o600);key.write_bytes(b'bad')
            self.assertNotEqual(subprocess.run(cmd+['public',str(key)],capture_output=True).returncode,0)


def main():
    global ARGS
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--build',type=Path,required=True);p.add_argument('--key-tool',type=Path,required=True)
    p.add_argument('--out',type=Path,required=True)
    ARGS=p.parse_args();ARGS.build=ARGS.build.resolve();ARGS.key_tool=ARGS.key_tool.resolve();ARGS.out=ARGS.out.resolve()
    ARGS.out.mkdir(parents=True,exist_ok=True)
    os.environ.update(FUNC_PATH=str(ARGS.build/'crypto/func'),FIFT_PATH=str(ARGS.build/'crypto/fift'),
        TOL_PATH=str(ARGS.build/'tol/tol'),EMULATOR_PATH=str(emulator_library(ARGS.build)))
    build_contracts(ARGS.build,ARGS.out)
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(SDKNativeTests))
    (ARGS.out/'sdk.json').write_text(json.dumps({'success':result.wasSuccessful(),'network':GLOBAL_ID,
        'source_commit':source_commit(),'scope':'native-emulator','events':RESULTS},indent=2,sort_keys=True)+'\n')
    return 0 if result.wasSuccessful() else 1


if __name__=='__main__':
    sys.exit(main())
