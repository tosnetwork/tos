"""Compare actual native/Rust libraries with frozen bytes and the public-data oracle."""
import argparse,copy,gzip,hashlib,json,subprocess,sys,tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'test/validator-auth-p0'))
import reference as r
from ed25519_oracle import Verifier,L,P

def main(cpp,rust,out,core_only=False):
 drivers=[str(cpp.resolve()),str(rust.resolve())]; report={'codec_types':0,'codec_negative_inputs':0,'crypto_cases':0}
 with tempfile.TemporaryDirectory() as d:
  d=Path(d)
  def run(args,expected):
   for exe in drivers:
    p=subprocess.run([exe,*map(str,args)],capture_output=True,text=True)
    if p.returncode not in (0,1):raise RuntimeError(("driver failure",p.returncode,p.stderr))
    if p.returncode != (0 if expected else 1):raise AssertionError((exe,args,p.returncode,p.stderr))
  g=json.loads((ROOT/'test/validator-auth-p0/lifecycle-api-golden.json').read_text())
  for kind,h in g['objects'].items():
   raw=bytes.fromhex(h);(d/'in').write_bytes(raw)
   for exe in drivers:
    p=subprocess.run([exe,'codec',kind,str(d/'in'),str(d/'out')],capture_output=True,text=True)
    if p.returncode not in (0,1):raise RuntimeError(("driver failure",p.returncode,p.stderr))
    assert p.returncode==0,(kind,p.stderr)
    assert (d/'out').read_bytes()==raw,kind
   report['codec_types']+=1
   for bad in (raw[:-1],raw+b'\0'):
    (d/'in').write_bytes(bad);run(['codec',kind,d/'in',d/'out'],False);report['codec_negative_inputs']+=1
  for bad in g['negatives']:
   (d/'in').write_bytes(bytes.fromhex(bad['hex']));run(['codec',bad['kind'],d/'in',d/'out'],False);report['codec_negative_inputs']+=1
  v=Verifier()
  def crypto(key,message,sig):
   for name,value in (('key',key),('message',message),('signature',sig)):(d/name).write_bytes(value)
   run(['verify',d/'key',d/'message',d/'signature','unused'],v.verify(key,message,sig));report['crypto_cases']+=1
  frozen=json.loads(gzip.decompress((ROOT/'test/validator-auth-p0/golden.json.gz').read_bytes()))
  committee=r.decode('committee',bytes.fromhex(frozen['committee']))
  report['certificate_cases']=0
  for case in frozen['cases']:
   cert=r.decode('certificate',bytes.fromhex(case['certificate']))
   for mode in ('valid','exact-quorum','below-quorum','surplus-invalid','duplicate','wrong-context','key-epoch','payload-slot'):
    changed=copy.deepcopy(cert);expected=copy.deepcopy(cert['duty'])
    if mode=='exact-quorum':changed['records']=changed['records'][:2]
    if mode=='below-quorum':changed['records']=changed['records'][:1]
    if mode=='surplus-invalid':changed['records'][-1]['components'][0]['signature']=bytes(64)
    if mode=='duplicate':changed['records'][1]=changed['records'][0]
    if mode=='wrong-context':expected['network']+=1
    if mode=='key-epoch':changed['records'][0]['components'][0]['epoch']+=1
    if mode=='payload-slot':changed['payload']=changed['payload'][:-1]+bytes([changed['payload'][-1]^1])
    for name,value in (('policy',bytes.fromhex(frozen['policy'])),('committee',bytes.fromhex(frozen['committee'])),('cert',r.encode('certificate',changed)),('duty',r.encode('duty',expected))):(d/name).write_bytes(value)
    run(['certificate',d/'policy',d/'committee',d/'cert',d/'duty',d/'weight'],mode in ('valid','exact-quorum'))
    if mode in ('valid','exact-quorum'):assert (d/'weight').read_text()==str(3 if mode=='valid' else 2)
    report['certificate_cases']+=1
  for case in frozen['cases']:
   cert=r.decode('certificate',bytes.fromhex(case['certificate']))
   for row,member in zip(cert['records'],committee['members']):
    public=member['keys'][case['role']-1]['public_key'];message=r.statement(cert['duty'],row);sig=row['components'][0]['signature']
    crypto(public,message,sig)
    crypto(public,message+b'\0',sig)
    crypto(public,message,sig[:32]+L.to_bytes(32,'little'))
    crypto(public,message,sig[:-1])
    crypto(public,message,sig+b'\0')
  # Public scalar one: a valid R=identity signature under the frozen noncofactored rule.
  base=bytes.fromhex('58'+'66'*31);identity=(1).to_bytes(32,'little');message=b'public edge fixture'
  scalar=int.from_bytes(hashlib.sha512(identity+base+message).digest(),'little')%L
  crypto(base,message,identity+scalar.to_bytes(32,'little'))
  for key in (bytes(32),identity,(P+1).to_bytes(32,'little'),(1+(1<<255)).to_bytes(32,'little'),b'x'*31,b'x'*33,base):
   (d/'key').write_bytes(key);run(['admit',d/'key'],v.admit(key));report['crypto_cases']+=1
  for first in (bytes(32), (P+1).to_bytes(32,'little'), (1+(1<<255)).to_bytes(32,'little')):
   crypto(base,message,first+scalar.to_bytes(32,'little'))
  report['native_boc_cases']=0
  for size in (() if core_only else (1,120,121,1048576,33554432)):
   raw=hashlib.shake_256(b'native data').digest(size)
   (d/'raw').write_bytes(raw)
   subprocess.run([drivers[0],'pack',str(d/'raw'),str(d/'boc')],check=True)
   subprocess.run([drivers[0],'unpack',str(d/'boc'),str(d/'out')],check=True)
   assert (d/'out').read_bytes()==raw
   original=(d/'boc').read_bytes()
   for bad in (original[:-1],original+b'\0',original[:4]+bytes([original[4]^1])+original[5:]):
    (d/'bad').write_bytes(bad)
    result=subprocess.run([drivers[0],'unpack',str(d/'bad'),str(d/'out')],capture_output=True)
    assert result.returncode==1
   report['native_boc_cases']+=4
 report['success']=True;out.write_text(json.dumps(report,indent=2)+'\n');print(report)
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--cpp',type=Path,required=True);p.add_argument('--rust',type=Path,required=True);p.add_argument('--out',type=Path,required=True)
 p.add_argument('--core-only',action='store_true');a=p.parse_args();main(a.cpp,a.rust,a.out,a.core_only)
