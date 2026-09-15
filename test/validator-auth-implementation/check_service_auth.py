"""Real service signatures, independent trust and polling memory in both libraries."""
import argparse,copy,json,struct,subprocess,sys,tempfile
from pathlib import Path
from check_api_semantics import fixtures,ROOT
import reference as r,vectors
from test_lifecycle_api import h,ZERO

def main(driver,out=None):
 cases=fixtures();driver=str(Path(driver).resolve());seed=h(1);public,_=vectors.sign(seed,b'public')
 p1=dict(issuer=h(81),revision=1,previous=ZERO,suites=[dict(suite=1,parameters=1)])
 p2=dict(p1,revision=2,previous=r.object_id('service_policy',p1));keyid=h(85)
 permit=copy.deepcopy(cases[5][0]['permit']);permit['body'].update(issuer=p1['issuer'],service_policy=r.object_id('service_policy',p1))
 receipt=copy.deepcopy(cases[5][1]['receipt']);receipt['body'].update(issuer=p1['issuer'],service_policy=r.object_id('service_policy',p1))
 def sign(kind,value):
  value=copy.deepcopy(value);_,signature=vectors.sign(seed,r.encode(kind+'_body',value['body']))
  value['components']=[dict(suite=1,parameters=1,key_id=keyid,signature=signature)];return value
 permit=sign('permit',permit);receipt=sign('receipt',receipt);report=[]
 pc=struct.pack('>IQB',100,1,1)
 rc=struct.pack('>Q',receipt['body']['journal_sequence'])+r.object_id('receipt_body',receipt['body'])
 with tempfile.TemporaryDirectory(prefix='p0-service-') as folder:
  folder=Path(folder)
  def run(kind,value,expected,context,policies=(p1,),error=None,label=None):
   (folder/'count').write_bytes(bytes([len(policies)]))
   for i,p in enumerate(policies):
    (folder/f'trust-{i}-policy').write_bytes(r.encode('service_policy',p));(folder/f'trust-{i}-key').write_bytes(public);(folder/f'trust-{i}-id').write_bytes(keyid)
   (folder/'value').write_bytes(r.encode('request_state' if kind=='state' else kind,value));(folder/'expected').write_bytes(r.encode('request_state' if kind=='state' else kind+'_body',expected));(folder/'context').write_bytes(context)
   result=subprocess.run([driver,'service',kind,str(folder)],capture_output=True,text=True)
   if result.returncode not in (0,1):raise RuntimeError(('driver-failure',result.returncode,result.stderr))
   assert result.returncode==(1 if error else 0) and (not error or result.stderr.strip()==error),(label or kind,error,result.returncode,result.stderr)
   report.append(dict(kind=kind,label=label or 'valid',rejected=bool(error)))
  run('permit',permit,permit['body'],pc)
  run('permit',permit,permit['body'],struct.pack('>IQB',228,1,1),label='inclusive-expiry')
  run('permit',permit,permit['body'],struct.pack('>IQB',229,1,1),error='permit-current-coordinate',label='expired')
  run('permit',permit,permit['body'],struct.pack('>IQB',100,2,1),error='fenced',label='fenced')
  run('permit',permit,permit['body'],struct.pack('>IQB',100,1,0),error='duty-not-permitted',label='live-context')
  bad=copy.deepcopy(permit);bad['components'][0]['signature']=b'\x00'*64
  run('permit',bad,bad['body'],pc,error='service-signature',label='permit-signature')
  run('permit',permit,dict(permit['body'],audience=h(99)),pc,error='permit-context',label='permit-context')
  run('permit',permit,permit['body'],pc,policies=(p1,p2),error='stale-permit-policy',label='stale-policy')
  newer=copy.deepcopy(permit);newer['body']['service_policy']=r.object_id('service_policy',p2);newer=sign('permit',newer)
  run('permit',newer,newer['body'],pc,policies=(p1,p2),label='rotated-permit')
  run('permit',permit,permit['body'],pc,policies=(dict(p1,revision=2),),error='service-policy-history',label='policy-genesis')
  run('permit',permit,permit['body'],pc,policies=(p1,dict(p2,revision=3)),error='service-policy-history',label='policy-gap')
  run('receipt',receipt,receipt['body'],rc)
  run('receipt',receipt,receipt['body'],rc,policies=(p1,p2),label='historical-receipt')
  bad=copy.deepcopy(receipt);bad['components'][0]['signature']=b'\x00'*64
  run('receipt',bad,bad['body'],rc,error='service-signature',label='receipt-signature')
  run('receipt',receipt,receipt['body'],struct.pack('>Q',2)+h(199),error='receipt-frontier',label='receipt-frontier')
  run('receipt',receipt,dict(receipt['body'],audience=h(99)),rc,error='receipt-binding',label='receipt-context')
  state=copy.deepcopy(cases[6][1]);rid=state['request_id'];absent=dict(request_id=rid,state=0,statement_id=ZERO,fence=0,result=[],receipt=[])
  reserved=copy.deepcopy(state);reserved.update(state=1,result=[],receipt=[copy.deepcopy(receipt)]);reserved['receipt'][0]['body'].update(state=1,subject=state['statement_id'],request_id=rid,method=5,fence=1,result_hash=ZERO)
  burned=copy.deepcopy(reserved);burned['state']=3;burned['receipt'][0]['body']['state']=3
  for before,after in [(absent,reserved),(reserved,state),(reserved,burned),(state,state),(burned,burned)]:run('state',after,before,rid)
  run('state',absent,state,rid,error='terminal-state-regression',label='terminal-regression')
  run('state',absent,reserved,rid,error='reserved-state-regression',label='reserved-regression')
  changed=copy.deepcopy(state);changed['fence']=2;changed['result'][0]['fence']=2
  run('state',changed,reserved,rid,error='reserved-state-binding',label='reserved-binding')
  changed=copy.deepcopy(state);changed['result'][0]['record']['components'][0]['signature']=b'x'*64
  run('state',changed,state,rid,error='terminal-state-regression',label='terminal-byte-replacement')
 result=dict(service_auth_cases=len(report),cases=report,success=True)
 if out:Path(out).write_text(json.dumps(result,indent=2)+'\n')
 print(json.dumps({k:v for k,v in result.items() if k!='cases'}))
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--driver',required=True);p.add_argument('--out');a=p.parse_args();main(a.driver,a.out)
