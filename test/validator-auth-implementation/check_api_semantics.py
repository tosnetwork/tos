"""Semantic association through production code; proof fixtures carry no authority."""
import argparse,copy,hashlib,json,subprocess,sys,tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'test/validator-auth-p0'))
import api,reference as r,transfer as tr,vectors
from test_lifecycle_api import h,ZERO,anchor,proof,initial,update,key,evidence

def fixtures():
 v=vectors.build();env=r.decode('envelope',bytes.fromhex(v['cases'][0]['envelope']));signed=copy.deepcopy(env['record'])
 cert=r.decode('certificate',bytes.fromhex(v['cases'][0]['certificate']));d=cert['duty'];a=anchor()
 fingerprint=hashlib.sha256((ROOT/'doc/validator-auth-p0/profile.json').read_bytes()).digest()
 state,archive=initial();u=update(state,archive);k=key();policy=r.decode('policy',bytes.fromhex(v['policy']))
 def permit(method,subject,identity=state['identity'],duty=None):
  selected=d if duty is None else duty
  return dict(body=dict(issuer=h(81),service_policy=h(82),audience=h(83),network=selected['network'],genesis_root=selected['genesis_root'],genesis_file=selected['genesis_file'],anchor=a,registry_root=h(84),policy=selected['policy'],committee=selected['committee'],session=selected['session'],identity=identity,method=method,subject=subject,expires_mc=228,fence=1),components=[dict(suite=1,parameters=1,key_id=h(85),signature=b's'*64)])
 def finish(method,q,out):
  out['receipt']=dict(body=dict(issuer=h(91),service_policy=h(92),audience=h(93),request_id=api.request_id(method,q),method=method,subject=out['statement_id'] if method==5 else r.digest('api-subject',r.encode(api.METHODS[str(method)]['request'],q)),result_hash=api.result_hash(method,out),journal_sequence=2,fence=q['fence'],state=2,context_id=r.object_id('permit',q['permit']) if 'permit' in q else ZERO),components=[dict(suite=1,parameters=1,key_id=h(94),signature=b'r'*64)])
  return q,out
 cases={1:({},dict(interface_digest=fingerprint,installed=[dict(suite=1,parameters=1)],admitted=[dict(suite=1,parameters=1)],max_request=2000000,max_result=2000000,persistent_journal=1,fencing=1,stateful=0)),2:(dict(key_id=r.object_id('key',k)),k)}
 q=dict(preparation_id=h(1),**{n:k[n] for n in ('identity','role','suite','parameters','epoch','valid_from','valid_until')},mode=0,provider_handle=ZERO,fence=1)
 cases[3]=finish(3,q,dict(prepared=dict(key=k,handle=h(95))))
 auth=evidence(u,state);auth['possession']=[];new=r.decode('key',u['new_key']);uid=r.object_id('update',u)
 q=dict(key=new,handle=h(95),update=u,authorizations=auth,permit=permit(4,uid),fence=1)
 cases[4]=finish(4,q,dict(key=new,possession=dict(update_id=uid,key=r.keyref(new),signature=b'p'*64)))
 for c in env['record']['components']:c['signature']=b''
 statement=r.statement(env['duty'],env['record']);sid=r.digest('statement',statement)
 q=dict(request_id=r.digest('sign-request',statement),key_handles=[h(95)],envelope_template=r.encode('envelope',env),permit=permit(5,sid,env['record']['identity'],env['duty']),fence=1)
 cases[5]=finish(5,q,dict(request_id=q['request_id'],statement_id=sid,record=signed,fence=1))
 cases[6]=(dict(request_id=q['request_id']),dict(request_id=q['request_id'],state=2,statement_id=sid,fence=1,result=[cases[5][1]],receipt=[]))
 retire=update(state,archive,op=3);uid=r.object_id('update',retire)
 q=dict(key_id=retire['old_key'],update=retire,authorizations=evidence(retire,state),permit=permit(7,uid),fence=1)
 cases[7]=finish(7,q,dict(key_id=q['key_id'],update_id=uid))
 pid=r.object_id('policy',policy);ps=dict(interface_digest=fingerprint,policy=pid,active=policy['suites'])
 cases[8]=(dict(anchor=a),dict(anchor=a,**ps,installed=policy['suites'],can_parse=1,can_verify=1,proof=proof(6,r.object_id('profile_state',ps))))
 cases[9]=(dict(anchor=a,policy_id=pid),dict(anchor=a,policy=policy,proof=proof(2,pid)))
 q=dict(anchor=a,limit=2,cursor=[]);qid=api.query_id(a,2);identities=[state];cursors=[]
 pageid=r.digest('registry-page',qid+ZERO+b'\x01'+r.encode('identity',state)+b'\x00')
 cases[10]=(q,dict(anchor=a,query_id=qid,identities=identities,cursor=cursors,proof=proof(3,pageid)))
 kid=r.object_id('key',k);cases[11]=(dict(anchor=a,key_id=kid),dict(anchor=a,key=k,proof=proof(4,kid)))
 cert_raw=r.encode('certificate',cert);cid=r.object_id('certificate',cert)
 cases[12]=(dict(anchor=a,certificate_id=cid),dict(anchor=a,era=1,interface_digest=fingerprint,certificate=tr.value(cert_raw,4),committee=proof(5,d['committee']),policy=proof(2,d['policy'])))
 cases[13]=(dict(anchor=a,certificate=tr.value(cert_raw,4),committee=proof(5,d['committee']),policy=proof(2,d['policy'])),dict(anchor=a,certificate_id=cid,policy=d['policy'],committee=d['committee'],duty=r.object_id('duty',d),signers=[row['identity'] for row in cert['records']],weight=3))
 chunk=b'x'*70000;manifest=tr.manifest(chunk,7);mid=r.object_id('object_ref',manifest)
 cases[14]=(dict(anchor=a,manifest=manifest,index=0),dict(anchor=a,manifest_id=mid,index=0,data=chunk))
 cases[15]=(dict(anchor=a,manifest=manifest,index=0,data=chunk),dict(anchor=a,manifest_id=mid,index=0))
 return cases

def main(driver,out=None):
 driver=str(Path(driver).resolve());cases=fixtures();report=[]
 with tempfile.TemporaryDirectory(prefix='p0-api-') as folder:
  folder=Path(folder)
  def run(method,q,result,mode='response',error=None,label=None):
   (folder/'request').write_bytes(r.encode(api.METHODS[str(method)]['request'],q));(folder/'response').write_bytes(r.encode(api.METHODS[str(method)]['result'],result))
   process=subprocess.run([driver,str(method),mode,str(folder/'request'),str(folder/'response'),str(folder)],capture_output=True,text=True)
   if process.returncode not in (0,1):raise RuntimeError(('harness-failure',process.returncode,process.stderr))
   assert process.returncode==(1 if error else 0) and (not error or process.stderr.strip()==error),(label or method,error,process.returncode,process.stderr)
   report.append(dict(method=method,mode=mode,label=label or 'valid',rejected=bool(error)))
  for method,(q,result) in cases.items():
   api.validate_request(method,q);api.validate_response(method,q,result)
   run(method,q,result,'request');run(method,q,result)
  def negative(method,path,value,error,mode='response',label=None):
   q,result=(copy.deepcopy(value) for value in cases[method]);target=q if mode=='request' else result
   for part in path[:-1]:target=target[part]
   target[path[-1]]=value
   run(method,q,result,mode,error,label or error)
  for n in (3,4,5,7):
   for field,value in [('request_id',h(250)),('method',1),('subject',h(250)),('result_hash',h(250)),('context_id',h(250)),('fence',2),('journal_sequence',0),('state',1)]:
    negative(n,['receipt','body',field],value,'result-receipt-binding',label=f'receipt-{n}-{field}')
  negative(1,['interface_digest'],h(250),'interface-digest')
  negative(1,['fencing'],2,'capability-bounds')
  negative(1,['max_request'],2000001,'capability-bounds')
  negative(1,['admitted'],[dict(suite=2,parameters=1)],'capability-profiles')
  negative(2,['epoch'],2,'response-key')
  negative(3,['prepared','handle'],ZERO,'prepared-binding')
  negative(3,['prepared','key','epoch'],2,'prepared-binding')
  negative(3,['epoch'],0,'preparation','request')
  negative(3,['provider_handle'],h(1),'preparation-mode','request')
  negative(4,['possession','update_id'],h(250),'staged-binding')
  negative(4,['possession','signature'],b'p'*63,'staged-binding')
  negative(4,['authorizations','owner'],[],'stage-authorizations','request')
  negative(4,['permit','body','subject'],h(250),'permit-association','request')
  negative(5,['statement_id'],h(250),'sign-result-binding')
  negative(5,['record','components',0,'signature'],b's'*63,'sign-result-signatures')
  negative(5,['request_id'],h(250),'sign-request-id','request')
  negative(5,['key_handles'],[ZERO],'sign-template','request')
  negative(5,['permit','body','registry_root'],ZERO,'permit-shape','request')
  negative(5,['permit','body','network'],0,'sign-permit-association','request')
  negative(6,['state'],4,'state-code')
  negative(6,['result'],[],'complete-shape')
  negative(7,['update_id'],h(250),'retirement-binding')
  negative(7,['key_id'],h(250),'retire-key','request')
  negative(7,['authorizations','administration'],[],'retire-authorizations','request')
  for n in range(8,16):
   negative(n,['anchor','state'],h(250),'response-anchor',label=f'anchor-{n}')
   negative(n,['anchor','root'],ZERO,'anchor','request',label=f'anchor-request-{n}')
  negative(8,['can_parse'],0,'profile-flags')
  negative(8,['active'],[dict(suite=0,parameters=1)],'profile-suites')
  negative(8,['proof','object_id'],h(250),'proof-binding')
  negative(9,['policy','revision'],2,'response-policy')
  negative(10,['query_id'],h(250),'page-query')
  negative(10,['identities'],[cases[10][1]['identities'][0]]*2,'page-order')
  negative(10,['cursor'],[dict(anchor=anchor(),query_id=cases[10][1]['query_id'],last_identity=h(250))],'page-cursor')
  negative(10,['limit'],0,'page-limit','request')
  negative(11,['key','epoch'],2,'response-key')
  negative(11,['proof','proof_hash'],h(250),'proof-hash')
  negative(12,['era'],0,'certificate-era')
  negative(12,['interface_digest'],h(250),'certificate-era')
  negative(12,['committee','kind'],2,'proof-binding')
  original=cases[13][1]['signers']
  for name,signers in [('omitted',original[:-1]),('added',original+[h(250)]),('replaced',[h(240),h(241),h(242)])]:
   negative(13,['signers'],signers,'verified-signers',label='verified-signers-'+name)
  negative(13,['weight'],0,'verified-signers')
  negative(13,['certificate_id'],h(250),'verified-binding')
  negative(13,['committee','object_id'],h(250),'proof-binding','request')
  for n in (14,15):
   negative(n,['manifest_id'],h(250),'chunk-correlation')
   negative(n,['index'],1,'chunk-correlation')
   negative(n,['index'],1,'chunk-index','request')
  negative(14,['data'],b'y'*70000,'chunk-hash')
  negative(15,['data'],b'y'*70000,'chunk-hash','request')
  # Complete attachments are independently hashed by the oracle. These bytes
  # exercise transport integrity only and intentionally are not native proofs.
  q,res=(copy.deepcopy(value) for value in cases[8]);large=b'z'*70000
  ref=tr.manifest(large,5);(folder/ref['object_id'].hex()).write_bytes(large)
  res['proof']['proof']=tr.value(large,5);res['proof']['proof_hash']=r.digest('proof',large)
  run(8,q,res,label='referenced-proof')
  (folder/ref['object_id'].hex()).write_bytes(b'y'*70000)
  run(8,q,res,error='chunk-hash',label='referenced-chunk-hash')
  (folder/ref['object_id'].hex()).write_bytes(large)
  fake=copy.deepcopy(ref);fake['object_id']=h(252)
  fake['chunk_hashes']=[r.digest('object-chunk',fake['object_id']+b'\x00'+large)]
  (folder/fake['object_id'].hex()).write_bytes(large)
  res['proof']['proof']['reference']=[fake]
  run(8,q,res,error='object-hash',label='referenced-whole-hash')
  q,res=(copy.deepcopy(value) for value in cases[13]);large=b'z'*(32*1024*1024)
  ref=tr.manifest(large,5);(folder/ref['object_id'].hex()).write_bytes(large)
  for name in ('committee','policy'):
   q[name]['proof']=tr.value(large,5);q[name]['proof_hash']=r.digest('proof',large)
  run(13,q,res,error='attachment-budget',label='aggregate-attachment-budget')
 result=dict(api_semantic_cases=len(report),methods=15,cases=report,success=True)
 if out:Path(out).write_text(json.dumps(result,indent=2)+'\n')
 print(json.dumps({k:v for k,v in result.items() if k!='cases'}))
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--driver',required=True);p.add_argument('--out');a=p.parse_args();main(a.driver,a.out)
