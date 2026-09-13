"""Export independent public C0 context, PoP and identity-authority inputs."""
import argparse,copy,gzip,json,struct,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'test/validator-auth-p0'))
import reference as r,vectors as v
Z=bytes(32);h=v.h

def main(out):
 out.mkdir(parents=True,exist_ok=False)
 frozen=json.loads(gzip.decompress((ROOT/'test/validator-auth-p0/golden.json.gz').read_bytes()))
 policy=r.decode('policy',bytes.fromhex(frozen['policy']));committee=r.decode('committee',bytes.fromhex(frozen['committee']))
 cert=r.decode('certificate',bytes.fromhex(next(c['certificate'] for c in frozen['cases'] if c['role']==5)))
 cert['records']=cert['records'][:1]
 keys=committee['members'][0]['keys'];identity=dict(identity=h(11),stake_id=h(21),owner_workchain=-1,owner_address=h(22),next_nonce=8,previous=Z,active=[dict(role=k['role'],key=r.keyref(k)) for k in keys],pending=[])
 new=copy.deepcopy(keys[0]);new.update(epoch=2,valid_from=200)
 update=dict(operation=2,identity=h(11),nonce=8,previous=r.object_id('identity',identity),effective_from=200,old_key=r.object_id('key',keys[0]),new_key=r.encode('key',new),new_policy=b'',operation_data=b'')
 base=dict(policy=policy,committee=committee,identity=identity,key=new,update=update,certificate=cert,expected=copy.deepcopy(cert['duty']),payload=cert['payload'],chain=dict(network=42,genesis_root=h(51),genesis_file=h(52),chain_domain=h(70)),origin=dict(native_options_hash=h(53),vertical_seqno=7,key_block_seqno=9),inclusion=100,key_count=1)
 def chainbytes(c):return struct.pack('>i',c['network'])+c['genesis_root']+c['genesis_file']
 def session(c,admin=False):return r.digest('admin-session',chainbytes(c['chain'])+c['identity']['identity']) if admin else r.digest('session',chainbytes(c['chain'])+r.object_id('committee',c['committee'])+c['origin']['native_options_hash']+struct.pack('>II',c['origin']['vertical_seqno'],c['origin']['key_block_seqno']))
 def popbytes(c):
  raw=r.encode('update',c['update'])
  return b'TOS/P0/pop/v1\0'+struct.pack('>i',c['chain']['network'])+c['chain']['chain_domain']+struct.pack('>I',len(raw))+raw+r.object_id('key',c['key'])
 def setpop(c):
  _,sig=v.sign(h(1),popbytes(c));c['pop']=dict(update_id=r.object_id('update',c['update']),key=r.keyref(c['key']),signature=sig)
 setpop(base)
 admin=copy.deepcopy(base);admin['key']=copy.deepcopy(keys[4])
 def signcert(c):
  for row in c['certificate']['records']:
   _,sig=v.sign(h(1),r.statement(c['certificate']['duty'],row));row['components'][0]['signature']=sig
 def rebindkey(c):
  ref=r.keyref(c['key']);c['identity']['active'][4]['key']=ref
  c['certificate']['records'][0]['components']=[dict(ref,signature=b'')]
  signcert(c)
 def expected(mode,c):
  if mode in (1,2):return session(c,mode==2)
  if mode==3:
   d=copy.deepcopy(c['expected']);d.update(network=c['chain']['network'],genesis_root=c['chain']['genesis_root'],genesis_file=c['chain']['genesis_file'],committee=r.object_id('committee',c['committee']),policy=r.object_id('policy',c['policy']),workchain=-1 if d['role']==5 else c['committee']['workchain'],shard=1<<63 if d['role']==5 else c['committee']['shard'],anchor_mc=c['committee']['anchor_mc'],catchain=c['committee']['catchain'],payload_hash=r.digest('payload',bytes([d['role']])+c['payload']))
   return r.encode('duty',d)
  return popbytes(c) if mode==4 else b'\1'
 cases=[]
 def add(label,mode,change=None,error=None,source=None):
  c=copy.deepcopy(source if source is not None else admin if mode==6 else base)
  if change:change(c)
  cases.append((label,mode,c,error,b'' if error else expected(mode,c)))
 add('session-full-origin',1);add('admin-session-target',2)
 for mode in (1,2,3):
  for field in ('genesis_root','genesis_file','chain_domain'):
   add(f'context-{mode}-{field}',mode,lambda c,f=field:c['chain'].update({f:Z}),'chain-context')
 for f in ('network','genesis_root','genesis_file'):
  add('session-change-'+f,1,lambda c,f=f:c['chain'].update({f:-239 if f=='network' else h(88)}))
 for f in ('native_options_hash','vertical_seqno','key_block_seqno'):
  add('session-change-'+f,1,lambda c,f=f:c['origin'].update({f:h(88) if f=='native_options_hash' else 99}))
 add('admin-zero-target',2,lambda c:c['identity'].update(identity=Z))
 add('admin-other-target',2,lambda c:c['identity'].update(identity=h(99)))
 for case in frozen['cases']:
  def use(c,case=case):
   cert_=r.decode('certificate',bytes.fromhex(case['certificate']));c['expected']=cert_['duty'];c['payload']=cert_['payload']
  add('duty-role-'+str(case['role']),3,use)
 add('duty-admin-shard-normalization',3,lambda c:c['committee'].update(workchain=0,shard=1<<62))
 add('duty-session-zero',3,lambda c:c['expected'].update(session=Z),'session')
 add('duty-payload-bound',3,lambda c:c.update(payload=b'x'*4097),'payload-bound')
 add('duty-role-zero',3,lambda c:c['expected'].update(role=0),'role-position')
 add('duty-admin-nonce',3,lambda c:c['expected'].update(position=9),'admin-payload')
 add('pop-preimage',4);add('pop-real-signature',5)
 add('pop-pre-genesis',5,lambda c:c['chain'].update(genesis_root=Z,genesis_file=Z))
 add('pop-chain-domain',4,lambda c:c['chain'].update(chain_domain=Z),'chain-domain')
 add('pop-preimage-bound',4,lambda c:c['update'].update(new_key=b'x'*32768),'blob-bound')
 add('pop-signature',5,lambda c:c['pop'].update(signature=b'x'*64),'possession-signature')
 add('pop-network',5,lambda c:c['chain'].update(network=43),'possession-signature')
 add('pop-domain-substitution',5,lambda c:c['chain'].update(chain_domain=h(71)),'possession-signature')
 add('pop-update-binding',5,lambda c:c['pop'].update(update_id=h(90)),'possession-binding')
 add('pop-keyref-binding',5,lambda c:c['pop']['key'].update(epoch=3),'possession-binding')
 def mismatched_descriptor(c):c['update']['new_key']=r.encode('key',dict(c['key'],epoch=3));setpop(c)
 add('pop-descriptor-bytes',5,mismatched_descriptor,'possession-key')
 for field,bad in [('identity',h(99)),('suite',2),('parameters',2),('role',0),('role',6),('capacity_domain',h(99)),('capacity_limit',1)]:
  def changed_descriptor(c,f=field,b=bad):c['key'][f]=b;c['update']['new_key']=r.encode('key',c['key']);setpop(c)
  add('pop-descriptor-'+field+'-'+str(bad if type(bad)==int else 1),5,changed_descriptor,'possession-key')
 def changed_operation(c):c['update']['operation']=3;setpop(c)
 add('pop-operation',5,changed_operation,'possession-key')
 def invalid_public(c):c['key']['public_key']=Z;c['update']['new_key']=r.encode('key',c['key']);setpop(c)
 add('pop-public-key',5,invalid_public,'public-key')
 add('identity-current-authority',6)
 add('identity-inclusive-freshness',6,lambda c:c.update(inclusion=228))
 add('identity-stale',6,lambda c:c.update(inclusion=229),'admin-freshness')
 add('identity-future-anchor',6,lambda c:c.update(inclusion=99),'admin-freshness')
 add('identity-expected-duty',6,lambda c:c['expected'].update(network=43),'identity-context')
 for field,bad in [('role',4),('workchain',0),('shard',1<<62)]:
  def change(c,f=field,b=bad):c['expected'][f]=b;c['certificate']['duty'][f]=b;signcert(c)
  add('identity-context-'+field,6,change,'identity-context')
 def target(c):
  u=r.decode('update',c['certificate']['payload']);u['identity']=h(99);c['certificate']['payload']=r.encode('update',u);c['certificate']['duty']['payload_hash']=r.digest('payload',b'\5'+c['certificate']['payload']);c['expected']=copy.deepcopy(c['certificate']['duty']);signcert(c)
 add('identity-target',6,target,'identity-target')
 add('identity-empty-records',6,lambda c:c['certificate'].update(records=[]),'identity-components')
 add('identity-governance-records',6,lambda c:c['certificate']['records'].append(copy.deepcopy(c['certificate']['records'][0])),'identity-components')
 add('identity-record-target',6,lambda c:c['certificate']['records'][0].update(identity=h(99)),'identity-components')
 for count in (0,2):add('identity-key-count-'+str(count),6,lambda c,n=count:c.update(key_count=n),'identity-components')
 add('identity-empty-components',6,lambda c:c['certificate']['records'][0].update(components=[]),'identity-components')
 for field,bad in [('valid_from',101),('valid_until',100),('epoch',0),('identity',h(99)),('role',1),('suite',2),('parameters',2)]:
  def change(c,f=field,b=bad):c['key'][f]=b;rebindkey(c)
  add('identity-key-'+field,6,change,'identity-key')
 add('identity-current-key',6,lambda c:c['identity']['active'][4]['key'].update(epoch=2),'identity-key-binding')
 def component(c):c['certificate']['records'][0]['components'][0]['key_id']=h(99);signcert(c)
 add('identity-signed-keyref',6,component,'identity-key-binding')
 add('identity-signature',6,lambda c:c['certificate']['records'][0]['components'][0].update(signature=b'x'*64),'identity-signature')
 def public(c):c['key']['public_key']=Z;rebindkey(c)
 add('identity-public-key',6,public,'public-key')
 def large(c):
  row=copy.deepcopy(c['certificate']['records'][0]);row['components'][0]['signature']=b'x'*65536;c['certificate']['records']=[row]*9
 add('identity-certificate-budget',6,large,'certificate-budget')
 for i,(label,mode,c,error,golden) in enumerate(cases):
  d=out/str(i);d.mkdir()
  for name,kind in [('policy','policy'),('committee','committee'),('identity','identity'),('key','key'),('update','update'),('pop','possession_auth'),('certificate','certificate'),('expected','duty')]:
   (d/name).write_bytes(r.encode(kind,c[name]))
  (d/'chain').write_bytes(chainbytes(c['chain'])+c['chain']['chain_domain']);(d/'origin').write_bytes(c['origin']['native_options_hash']+struct.pack('>II',c['origin']['vertical_seqno'],c['origin']['key_block_seqno']))
  (d/'payload').write_bytes(c['payload']);(d/'inclusion').write_bytes(struct.pack('>I',c['inclusion']));(d/'key-count').write_bytes(bytes([c['key_count']]))
  (d/'case').write_text(f'{mode} {label} {error or "-"}\n');(d/'golden').write_bytes(golden)
 (out/'complete').write_text(str(len(cases))+'\n');print('EXPORTED:',len(cases),'independent context/authority cases')
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',type=Path,required=True);main(p.parse_args().out)
