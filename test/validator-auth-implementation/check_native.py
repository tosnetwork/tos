"""Cross-check native Rust cells/proofs against actual C++ native fixtures."""
import argparse,hashlib,json,subprocess,tempfile
from pathlib import Path
def main(args):
 report=[];binary=str(args.rust.resolve())
 with tempfile.TemporaryDirectory(prefix='p0-native-') as tmp:
  tmp=Path(tmp)
  def run(command,success,label):
   result=subprocess.run(command,capture_output=True,text=True)
   if result.returncode not in (0,1):raise RuntimeError((label,result.returncode,result.stderr))
   assert result.returncode==(0 if success else 1),(label,success,result.returncode,result.stderr)
   report.append(dict(case=label,accepted=success))
  cells=args.cells.resolve();proofs=args.proofs.resolve()
  assert len(list(cells.glob('*.cell')))==int((cells/'complete').read_text())>0,'cell-fixture-completeness'
  assert len(list(proofs.glob('*.case')))==int((proofs/'complete').read_text())>0,'proof-fixture-completeness' 
  for meta in sorted(cells.glob('*.cell')):
   budget,accepted=meta.read_text().split()
   run([binary,'unpack',str(meta.with_suffix('.boc')),str(tmp/'output'),budget],accepted=='1',meta.stem)
  for meta in sorted(proofs.glob('*.case'),key=lambda p:int(p.stem)):
   method,network,accepted=meta.read_text().split();name=meta.stem
   run([binary,'proof',method,network,str(meta.with_suffix('.request')),str(meta.with_suffix('.response')),str(meta.with_suffix('.anchor')),str(proofs),str(tmp/'output')],accepted=='1','proof-'+name)
   if accepted=='1':assert (tmp/'output').read_bytes()==meta.with_suffix('.response').read_bytes(),('proof-'+name,'canonical-result')
  if not args.proof_only:
   for size in [1,120,121,480,481,65536,1048576,33554432]:
    raw=hashlib.shake_256(str(size).encode()).digest(size);(tmp/'raw').write_bytes(raw)
    for producer,consumer,label in [(str(args.cpp.resolve()),binary,'cpp-to-rust'),(binary,str(args.cpp.resolve()),'rust-to-cpp')]:
     run([producer,'pack',str(tmp/'raw'),str(tmp/'boc')],True,f'{label}-pack-{size}')
     run([consumer,'unpack',str(tmp/'boc'),str(tmp/'output')],True,f'{label}-unpack-{size}')
     assert (tmp/'output').read_bytes()==raw,(label,size,'native-bytes')
   for raw,label in [(b'','empty'),(b'x'*33554433,'oversized')]:
    (tmp/'raw').write_bytes(raw);run([binary,'pack',str(tmp/'raw'),str(tmp/'boc')],False,'pack-'+label)
   (tmp/'raw').write_bytes(b'x'*121);run([binary,'pack',str(tmp/'raw'),str(tmp/'boc')],True,'base-boc')
   boc=(tmp/'boc').read_bytes()
   for raw,label in [(boc[:-1],'truncated'),(boc+b'x','trailing'),(b'bad!'+boc[4:],'tag')]:
    (tmp/'bad').write_bytes(raw);run([binary,'unpack',str(tmp/'bad'),str(tmp/'output')],False,'boc-'+label)
 args.out.write_text(json.dumps(dict(native_cases=len(report),cases=report,success=True),indent=2)+'\n');print('PASS:',len(report),'Rust native cross-checks')
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--rust',type=Path,required=True);p.add_argument('--cpp',type=Path);p.add_argument('--cells',type=Path,required=True);p.add_argument('--proofs',type=Path,required=True);p.add_argument('--proof-only',action='store_true');p.add_argument('--out',type=Path,required=True);main(p.parse_args())
