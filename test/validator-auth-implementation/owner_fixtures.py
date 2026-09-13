"""Execute the existing native wallet and export successful/rolled-back approvals."""
import argparse, copy, hashlib, json, os, struct, subprocess, sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(ROOT/'test/auth-extensions'),str(ROOT/'test/validator-auth-p0'),str(ROOT/'test/mldsa-auth')]
from cells import Cell,from_boc
from native import NOW,Emulator,compile_contract,state_init,active_account,internal,external,outgoing,account_data
from protocol import emulator_library
from vectors import sign

def main(build,driver,out,workchain):
 build=build.resolve();driver=driver.resolve();out=out.resolve();out.mkdir()
 os.environ.update(FUNC_PATH=str(build/'crypto/func'),FIFT_PATH=str(build/'crypto/fift'),EMULATOR_PATH=str(emulator_library(build)))
 code=compile_contract('wallet3-code.fc',out/'wallet.boc')
 seed=bytes([19])*32;public,_=sign(seed,b'owner public fixture');data=Cell().uint(0,32).uint(1,32).raw(public)
 wallet=(workchain,int.from_bytes(state_init(code,data).hash,'big'))
 (out/'owner').write_bytes(struct.pack('>i',workchain)+wallet[1].to_bytes(32,'big'))
 subprocess.run([str(driver),'prepare',str(out)],check=True)
 body=from_boc((out/'body.boc').read_bytes());rows=[]
 contract=json.loads((ROOT/'doc/validator-auth-p0-native-owner.json').read_text())
 import reference as reference
 identity=reference.decode('identity',(out/'identity').read_bytes())
 update=reference.decode('update',(out/'update').read_bytes())
 values={'tag':int(contract['approval_body']['ordered_fields'][0][2],16),'version':contract['version'],'chain_domain':(5000).to_bytes(32,'big'),'stake_id':identity['stake_id'],'update_id':reference.object_id('update',update)}
 expected=Cell()
 for name,kind,*_ in contract['approval_body']['ordered_fields']:
  expected.raw(values[name]) if kind=='bits256' else expected.uint(values[name],int(kind[1:]))
 assert body.bits==expected.bits and not body.refs and len(body.bits)==contract['approval_body']['bits'],'machine-readable-owner-body'

 for name in ('accept','wrong-update','wrong-stake','wrong-domain','wrong-target','rollback'):
  approval=copy.deepcopy(body)
  if name.startswith('wrong-') and name!='wrong-target':
   offset={'wrong-domain':48,'wrong-stake':304,'wrong-update':560}[name]
   approval.bits=approval.bits[:offset]+str(1-int(approval.bits[offset]))+approval.bits[offset+1:]
  target=(-1,901 if name=='wrong-target' else 900)
  amount=200_000_000_000 if name=='rollback' else 1_000_000_000
  message=internal(wallet,target,approval,amount)
  payload=Cell().sint(42,32).uint(1,32).uint(NOW+60,32).uint(0,32).uint(1,8).ref(message)
  _,signature=sign(seed,payload.hash)
  signed=Cell().raw(signature);signed.bits+=payload.bits;signed.refs.extend(payload.refs)
  emulator=Emulator(16)
  try:
   initial=active_account(wallet,code,data,100_000_000_000)
   result=emulator.send(initial,external(wallet,signed))
   assert result['success'],(name,'emulator setup',result)
   detail=result['details'];assert detail['exit']==0,(name,detail)
   rollback=name=='rollback';assert detail['aborted']==rollback,(name,detail)
   assert detail['action']['success']==(not rollback),(name,detail)
   assert detail['action']['code']==(37 if rollback else 0),(name,detail)
   tx=from_boc(result['transaction']);after=from_boc(result['shard_account']);afterdata,_=account_data(after)
   expected=Cell().uint(int(not rollback),32).uint(1,32).raw(public)
   assert afterdata.hash==expected.hash,(name,'wallet-state-rollback')
   assert len(outgoing(tx))==int(not rollback),(name,'wallet-outgoing-count')
   (out/(name+'.boc')).write_bytes(tx.boc())
   rows.append({'case':name,'transaction_hash':tx.hash.hex(),**detail})
  finally:emulator.close()
 # A forged wallet signature must fail before execution, with checks enabled.
 invalid=copy.deepcopy(signed);invalid.bits=str(1-int(invalid.bits[0]))+invalid.bits[1:]
 emulator=Emulator(16)
 try:
  result=emulator.send(active_account(wallet,code,data),external(wallet,invalid))
  assert not result['success'] and result.get('vm_exit_code')==35,('owner-wallet-signature',result)
 finally:emulator.close()
 (out/'execution.json').write_text(json.dumps({'source_sha256':hashlib.sha256((ROOT/'crypto/smartcont/wallet3-code.fc').read_bytes()).hexdigest(),'code_hash':code.hash.hex(),'cases':rows,'invalid_signature_rejected':True},indent=2)+'\n')
 print('PASS: six actual owner wallet executions and invalid-signature refusal')
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__)
 for arg in ('build','driver','out'):p.add_argument('--'+arg,type=Path,required=True)
 p.add_argument('--workchain',type=int,choices=(-1,0),default=-1)
 a=p.parse_args();main(a.build,a.driver,a.out,a.workchain)
