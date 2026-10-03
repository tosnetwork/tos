import argparse, os, subprocess, sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'test/auth-extensions'))
from native import compile_contract
p=argparse.ArgumentParser();p.add_argument('--build',type=Path,required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args()
a.out.mkdir(parents=True,exist_ok=True)
os.environ.update(FUNC_PATH=str(a.build.resolve()/'crypto/func'),TOL_PATH=str(a.build.resolve()/'tol/tol'),FIFT_PATH=str(a.build.resolve()/'crypto/fift'))
for ext in ('fc','tol'):
 source=ROOT/f'test/pq-falcon512/probe.{ext}';asm=a.out/f'probe-{ext}.fif';boc=a.out/f'probe-{ext}.boc'
 env=dict(os.environ,TOL_STDLIB=str(ROOT/'crypto/smartcont/tol-stdlib'))
 cmd=[os.environ['FUNC_PATH'],'-SPA','-o',str(asm),str(ROOT/'crypto/smartcont/stdlib.fc'),str(source)] if ext=='fc' else [os.environ['TOL_PATH'],'-o',str(asm),str(source)]
 subprocess.run(cmd,check=True,env=env)
 script=a.out/f'probe-{ext}.run.fif';script.write_text(f'"Asm.fif" include\n"{asm.resolve()}" include\n2 boc+>B "{boc.resolve()}" B>file\n')
 subprocess.run([os.environ['FIFT_PATH'],'-I',str(ROOT/'crypto/fift/lib'),'-s',str(script)],check=True)
 path=a.out/'scenarios.tsv';rows=path.read_text().splitlines();good=next(x for x in rows if x.startswith('auth\t')).split('\t')
 good[0]='compiled-'+ext;rows.append('\t'.join(good+[boc.read_bytes().hex()]))
 good=good.copy();good[0]='compiled-invalid-'+ext;good[5]='I'
 sys.path.insert(0,str(ROOT/'test/falcon-auth'));from protocol import chain
 good[8]=chain(bytes(666)).boc().hex();rows.append('\t'.join(good+[boc.read_bytes().hex()]))
 path.write_text('\n'.join(rows)+'\n')
