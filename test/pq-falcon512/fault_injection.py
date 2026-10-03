"""Inject an unknown backend status and require FatalError in both real VMs."""
import argparse,json,subprocess,sys
from pathlib import Path
R=Path(__file__).resolve().parents[2]
p=argparse.ArgumentParser();p.add_argument('--build',type=Path,required=True);p.add_argument('--artifacts',type=Path,required=True);a=p.parse_args();b=a.build.resolve();out=a.artifacts.resolve()
path=R/'crypto/pq/falcon512-native.c';original=path.read_text();anchor='  /* Only logn=9 compressed coefficients'
if original.count(anchor)!=1:raise ValueError('fault injection target missing')
def build():
 subprocess.run(['cmake','--build',str(b),'--target','test-pq-falcon512-parity','-j','2'],cwd=R,check=True,stdout=subprocess.DEVNULL)
 subprocess.run(['cargo','build','--manifest-path','tosctl/src/Cargo.toml','--locked','--release','-p','tos_vm','--example','falcon-parity'],cwd=R,check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)

def equal(left,right):
 def normalize(text):
  rows=[x.split("\t") for x in text.splitlines()]
  for row in rows: row[5:]=[x.lower() for x in row[5:]]
  return rows
 return normalize(left)==normalize(right)

def run(driver,scenarios):
 return subprocess.check_output([str(driver),str(scenarios)],text=True,cwd=R)
row=next(x.split('\t') for x in (out/'scenarios.tsv').read_text().splitlines() if x.startswith('auth\t'))
scenarios=out/'fault-scenarios.tsv';scenarios.write_text('\n'.join('\t'.join(['fault-'+str(i)]+row[1:]) for i in range(20))+'\n')
cpp=b/'crypto/pq/test-pq-falcon512-parity';rust=R/'tosctl/src/target/release/examples/falcon-parity'
try:
 path.write_text(original.replace(anchor,'  return -2; /* TEST ONLY injected backend failure. */\n'+anchor));build()
 left,right=run(cpp,scenarios),run(rust,scenarios)
 if not equal(left,right) or any(x.split('\t')[1]!='12' or x.split('\t')[4]!='0' for x in left.splitlines()):
  raise AssertionError('backend fault did not become identical noncommitted FatalError')
finally:
 path.write_text(original);build()
left,right=run(cpp,scenarios),run(rust,scenarios)
if not equal(left,right) or any(x.split('\t')[1]!='0' or x.split('\t')[3]!='-1' for x in left.splitlines()):raise AssertionError('fault restoration failed')
(out/'backend-fault.json').write_text(json.dumps(dict(success=True,compiled=True,fault_exit=12,restored_valid=True,vm=['cpp','rust']))+'\n')
print('PASS: both VMs map injected backend failure to FatalError; restored signatures valid')
