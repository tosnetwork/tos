"""Differential native identity transitions with controlled independent authority results."""
import argparse,copy,json,subprocess,sys,tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'test/validator-auth-p0'))
import reference as r,lifecycle as lc,test_lifecycle_api as t

def main(cpp,out):
 count=0
 with tempfile.TemporaryDirectory() as folder:
  d=Path(folder);(d/'archive').mkdir()
  def inputs(state,archive):
   (d/'identity').write_bytes(r.encode('identity',state))
   for p in (d/'archive').iterdir():p.unlink()
   for id,key in archive.items():(d/'archive'/id.hex()).write_bytes(r.encode('key',key))
  def apply(state,archive,update,at=100,evidence=None,deny='none'):
   nonlocal count
   inputs(state,archive);evidence=t.evidence(update,state) if evidence is None else evidence
   (d/'update').write_bytes(r.encode('update',update));(d/'evidence').write_bytes(r.encode('authorizations',evidence))
   callbacks={k:(lambda *_,allowed=k!=deny:allowed) for k in t.VERIFIERS}
   expected=None
   try:expected=lc.apply(state,archive,update,evidence,at,callbacks,lambda k:(k['suite'],k['parameters'])==(1,1) and t.Verifier().admit(k['public_key']))
   except r.Refusal:pass
   p=subprocess.run([str(cpp),'apply',str(d/'identity'),str(d/'archive'),str(d/'update'),str(d/'evidence'),str(at),str(d/'out'),deny],capture_output=True,text=True)
   if p.returncode not in (0,1):raise RuntimeError(("driver failure",p.returncode,p.stderr))
   assert p.returncode==(0 if expected is not None else 1),p.stderr
   if expected is not None:assert (d/'out').read_bytes()==r.encode('identity',expected[0])
   count+=1;return expected
  state,archive=t.initial();update=t.update(state,archive)
  staged,keys=apply(state,archive,update)
  for deny in ('owner','possession','administration'):apply(state,archive,update,deny=deny)
  for field,value in [('nonce',0),('previous',t.h(99)),('effective_from',99),('old_key',t.h(98))]:
   bad=copy.deepcopy(update);bad[field]=value;apply(state,archive,bad)
  conflict=t.update(staged,keys);apply(staged,keys,conflict,150)
  cancel=t.update(staged,keys,op=7,effective=0);cancel['operation_data']=r.object_id('transition',staged['pending'][0])
  canceled,keys=apply(staged,keys,cancel,150)
  again=t.update(canceled,keys);apply(canceled,keys,again,150)
  bad=copy.deepcopy(cancel);bad['operation_data']=t.h(99);apply(staged,keys,bad,150)
  other,keys=apply(staged,keys,t.update(staged,keys,role=2,effective=210),150)
  current=other
  for height in range(151,212):
   inputs(current,keys);expected=lc._apply_due(current,keys,height)
   p=subprocess.run([str(cpp),'due',str(d/'identity'),str(d/'archive'),str(height-1),str(height),str(d/'out')],capture_output=True,text=True)
   if p.returncode not in (0,1):raise RuntimeError(("driver failure",p.returncode,p.stderr))
   assert p.returncode==0,p.stderr;assert (d/'out').read_bytes()==r.encode('identity',expected)
   current=expected;count+=1
  inputs(other,keys)
  p=subprocess.run([str(cpp),'due',str(d/'identity'),str(d/'archive'),'150','210',str(d/'out')],capture_output=True)
  if p.returncode not in (0,1):raise RuntimeError(("driver failure",p.returncode,p.stderr))
  assert p.returncode==1;count+=1
  retired,_=apply(current,keys,t.update(current,keys,op=3,effective=0),211)
  assert len(retired['active'])==4
  fresh=copy.deepcopy(state);fresh.update(next_nonce=0,active=[],pending=[],previous=t.ZERO)
  first=t.update(fresh,{},op=1,effective=100,role=5)
  new=r.decode('key',first['new_key']);new['epoch']=1;first['new_key']=r.encode('key',new)
  auth=t.evidence(first,fresh);auth['administration']=[]
  bootstrap,bootstrap_keys=apply(fresh,{},first,evidence=auth)
  apply(fresh,{},first,evidence=auth,deny='owner');apply(fresh,{},first,evidence=auth,deny='possession')
  wrong=t.update(fresh,{},op=1,effective=100,role=1);a=t.evidence(wrong,fresh);a['administration']=[]
  apply(fresh,{},wrong,evidence=a)
  ordinary=t.update(bootstrap,bootstrap_keys,op=1,effective=100,role=1)
  apply(bootstrap,bootstrap_keys,ordinary)
  for nonce in ((1<<64)-1,0,100):
   bad=t.update(state,archive);bad['nonce']=nonce;apply(state,archive,bad)
  for epoch in (0,(1<<64)-1):
   bad=t.update(state,archive);key=r.decode('key',bad['new_key']);key['epoch']=epoch;bad['new_key']=r.encode('key',key);apply(state,archive,bad)
  for effective in (100+65536,100+65537,(1<<32)-1):
   bad=t.update(state,archive,effective=effective);key=r.decode('key',bad['new_key']);key['valid_until']=min((1<<32)-1,effective+1000);bad['new_key']=r.encode('key',key);apply(state,archive,bad)
  for name in ('owner','possession','administration'):
   a=t.evidence(update,state);a[name]=[];apply(state,archive,update,evidence=a)
  bad=copy.deepcopy(update);key=r.decode('key',bad['new_key']);key['suite']=2;bad['new_key']=r.encode('key',key);apply(state,archive,bad)
  def select(view,history,height,role):
   nonlocal count
   inputs(view,history);expected=None
   try:expected=lc.snapshot(view,history,height,[(role,1,1)])[0]
   except r.Refusal:pass
   process=subprocess.run([str(cpp),'select',str(d/'identity'),str(d/'archive'),str(height),str(role),str(d/'out')],capture_output=True,text=True)
   if process.returncode not in (0,1):raise RuntimeError(('driver failure',process.returncode,process.stderr))
   assert process.returncode==(0 if expected is not None else 1),(height,role,process.stderr)
   if expected is not None:assert (d/'out').read_bytes()==r.encode('key',expected)
   count+=1;return None if expected is None else r.encode('key',expected)
  for role in range(1,6):select(state,archive,100,role)
  old=select(state,archive,199,1)
  select(staged,keys,200,1)
  next_view=lc._apply_due(staged,keys,200)
  new=select(next_view,keys,200,1);assert old!=new
  assert select(state,archive,199,1)==old
  select(state,archive,1000,1)
  select(bootstrap,bootstrap_keys,100,1)


 out.write_text(json.dumps(dict(success=True,cases=count,scope='native per-identity apply and replay; native authority proofs are separate'),indent=2)+'\n');print('PASS:',count,'native lifecycle cases')
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--cpp','--driver',dest='cpp',required=True,type=Path);p.add_argument('--out',required=True,type=Path);a=p.parse_args();main(a.cpp.resolve(),a.out)
