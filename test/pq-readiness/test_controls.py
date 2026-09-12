#!/usr/bin/env python3
"""Fail-closed readiness proposals and relayer state-machine unit tests.

Fake transports below test orchestration, not network execution. Real contract
execution and signatures are covered separately by test_sdk.py.
"""
import asyncio
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(ROOT/'test/tostester/src'),str(ROOT/'tools/pq')]
from activation import plan
from contract.pq_auth import AuthRequest,AuthState
from contract.pq_relayer import (PqRelayer,AttemptJournal,FundingBudget,ChainSnapshot,AttemptReceipt,LOSS_ACK)
from pytosiq_core import Address,Cell


class Controls(unittest.TestCase):
    def test_budget_checked_and_no_floats(self):
        self.assertEqual(FundingBudget(1,2,3,4,10).total,10)
        for values in [(1,2,3,4,9),(-1,2,3,4,10),(1.0,2,3,4,10),(2**120,2,3,4,2**120)]:
            with self.assertRaises(ValueError):FundingBudget(*values).total

    def test_activation_is_proposal_only_and_missing_evidence_fails(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);commit='a'*40
            doc={'network':42,'current_version':15,'target_version':16,'capabilities':123,
                 'release_commit':commit,'approvals':{},'validators':[{'id':'validator-1','acknowledged':True,'supports_version':16,'release_commit':commit}], 'evidence':{}}
            for name in ('security_review','nonrefundable_loss_model','release','validator_operations'):
                doc['approvals'][name]={'accepted':True,'owner':'TEST OWNER','reference':'TEST ONLY'}
            for name in ('rust_cpp_parity','module_e2e','production_load','activation_rehearsal'):
                f=root/(name+'.json');f.write_text(json.dumps({'success':True,'network':42,'source_commit':commit,'qualification':'production-validator'}))
                doc['evidence'][name]={'path':f.name,'sha256':hashlib.sha256(f.read_bytes()).hexdigest()}
            approved=plan(doc,root);self.assertFalse(approved['network_activated'])
            self.assertTrue(approved['proposal_only']);self.assertEqual(approved['config8_payload_hex'],'c400000010000000000000007b')
            for name in doc['approvals']:
                mutant=json.loads(json.dumps(doc));mutant['approvals'][name]['accepted']=False
                with self.assertRaises(ValueError):plan(mutant,root)
            for name in doc['evidence']:
                mutant=json.loads(json.dumps(doc));mutant['evidence'][name]['sha256']='0'*64
                with self.assertRaises(ValueError):plan(mutant,root)
            for field,value in [('supports_version',15),('acknowledged',False),('release_commit','b'*40)]:
                mutant=json.loads(json.dumps(doc));mutant['validators'][0][field]=value
                with self.assertRaises(ValueError):plan(mutant,root)
            f=root/'production_load.json';report=json.loads(f.read_text());report['qualification']='ci';f.write_text(json.dumps(report))
            doc['evidence']['production_load']['sha256']=hashlib.sha256(f.read_bytes()).hexdigest()
            with self.assertRaises(ValueError):plan(doc,root)

    def test_relayer_unknown_is_durable_and_receipts_are_not_broadcast_success(self):
        async def exercise(root):
            account=Address((0,bytes([1])*32));module=Address((0,bytes([2])*32));pk=bytes(1312)
            req=AuthRequest(42,account,1,0,1600,0,Cell.empty())
            class Signer:
                def public_key(self):return pk
                def sign(self,*args):return bytes(2420)
            class Transport:
                count=0;fail=False;version=16
                async def snapshot(self,a,m):return ChainSnapshot(42,self.version,1000,a,m,AuthState(2,1,0,m.hash_part),pk,'TEST BLOCK')
                async def estimate(self,*args):return FundingBudget(1,2,3,4,10)
                async def submit_internal(self,*args):
                    self.count+=1
                    if self.fail:raise TimeoutError('ambiguous broadcast')
                    return 'broadcast-id'
                async def receipt(self,*args):return AttemptReceipt(req.commitment.hex(),module,account,True,None,None,'module-tx')
            t=Transport();journal=AttemptJournal(root/'journal.db');relay=PqRelayer(t,journal)
            with self.assertRaises(ValueError):await relay.submit(req,module,Signer(),'')
            self.assertEqual(t.count,0)
            t.version=15
            with self.assertRaises(ValueError):await relay.submit(req,module,Signer(),LOSS_ACK)
            t.version=16;t.fail=True
            with self.assertRaises(TimeoutError):await relay.submit(req,module,Signer(),LOSS_ACK)
            self.assertEqual(t.count,1);journal.close()
            journal=AttemptJournal(root/'journal.db');relay=PqRelayer(t,journal)
            with self.assertRaises(ValueError):await relay.submit(req,module,Signer(),LOSS_ACK)
            self.assertEqual(t.count,1)
            receipt=await relay.reconcile(req,module,'broadcast-id');self.assertEqual(receipt.status,'pending')
            self.assertEqual(replace(receipt,account_success=True,account_nonce_consumed=True,account_transaction='account-tx').status,'executed')
            self.assertEqual(replace(receipt,account_success=False,account_nonce_consumed=False,account_transaction='account-tx').status,'account_rejected')
            journal.close()
        with tempfile.TemporaryDirectory() as d:asyncio.run(exercise(Path(d)))


if __name__=='__main__':unittest.main(verbosity=2)
