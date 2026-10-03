"""Full-VM valid/invalid/maximal input calibration, with fixed paid-call checks."""
import argparse,json,subprocess,time
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--cpp',type=Path,required=True);p.add_argument('--rust',type=Path,required=True);p.add_argument('--scenarios',type=Path,required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args()
a.out.mkdir(parents=True,exist_ok=True);data=[x.split('\t') for x in a.scenarios.read_text().splitlines()]
reports=[]
for name in ('auth','max','signature-byte-300'):
 row=next(x for x in data if x[0]==name);iterations=500
 path=a.out/(name+'.tsv');path.write_text('\n'.join('\t'.join([name+'-'+str(i)]+row[1:]) for i in range(iterations))+'\n')
 for vm,driver in [('cpp',a.cpp),('rust',a.rust)]:
  start=time.perf_counter();r=subprocess.run([str(driver.resolve()),str(path)],capture_output=True,text=True,check=True);seconds=time.perf_counter()-start
  rows=[x.split('\t') for x in r.stdout.splitlines()]
  if len(rows)!=iterations or any(int(x[1])!=0 or int(x[2])<20000 or int(x[3])!=(-1 if row[5]=='V' else 0) for x in rows):raise ValueError('invalid full VM calibration')
  reports.append(dict(case=name,vm=vm,iterations=iterations,microseconds=seconds*1e6/iterations,gas=int(rows[0][2])))
 path.unlink()
(a.out/'benchmark.json').write_text(json.dumps(dict(proposed_base_gas=20000,activation=False,scope='host full-VM bounded load; not complete node flood qualification',measurements=reports),indent=2)+'\n')
print(json.dumps(reports))
