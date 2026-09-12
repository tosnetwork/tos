#!/usr/bin/env python3
"""Execute the test-wallet CLI, not host acceptance or a deployed wallet."""
import argparse
from pathlib import Path
import subprocess
import tempfile
p=argparse.ArgumentParser();p.add_argument('--wallet',type=Path,required=True);args=p.parse_args()
wallet=str(args.wallet.resolve())
base=dict(secret=3,old_value=10000,old_blind=5,new_blind=7,aux_blind=11,
          fee=11,principal=137,outward_fee=17,max_balance=100000,max_value=1000,
          domain='2a'*80,withdrawal_id='07'*32,attempt_id='08'*32,context='2a'*566)
with tempfile.TemporaryDirectory() as t:
 root=Path(t)
 def run(label,mode,values,okay=True):
  request=root/(label+'.request');output=root/(label+'.out')
  request.write_text(''.join(f'{k}={v}\n' for k,v in values.items()))
  r=subprocess.run([wallet,mode,str(request),str(output)],capture_output=True,text=True)
  assert (r.returncode==0)==okay,(label,r.returncode,r.stderr)
  assert output.exists()==okay,(label,'unexpected publication')
  print(label,'exit',r.returncode)
  return dict(line.split('=',1) for line in output.read_text().splitlines()) if okay else {}
 points=run('d78-points','withdrawal-points',base)['points']
 # Independently reconstruct new available with the seed mode at old-debit.
 seed=run('seed-new-balance','seed',dict(base,old_value=9835,old_blind=7))['available']
 assert points[:128]==seed,'wrong x+q+f debit'
 assert len(points)==192,'three wallet-supplied points'
 proof=run('d78-prove','withdrawal-prove',base)
 assert {k:len(v)//2 for k,v in proof.items()}==dict(commitments=256,responses=192,range_proof=864)
 run('obsolete-field','withdrawal-points',dict(base,return_reserve=23),False)
 run('overflow','withdrawal-points',dict(base,principal=2**64-1,outward_fee=1),False)
 run('insufficient','withdrawal-points',dict(base,old_value=164),False)
 print('WALLET_EXAMPLE_SMOKE_PASS; generated proof is not independently verified by this CLI smoke')
