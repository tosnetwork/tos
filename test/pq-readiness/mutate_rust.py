#!/usr/bin/env python3
"""A compiler error is not a killed Rust VM mutation."""
import argparse
import json
from pathlib import Path
import subprocess
import sys
from compare import check
ROOT=Path(__file__).resolve().parents[2]


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--scenarios',type=Path,required=True)
    p.add_argument('--cpp',type=Path,required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args()
    source=ROOT/'tosctl/src/vm/src/executor/pq.rs';original=source.read_text()
    mutants=[('verification','status == invalid_signature {\n        false','status == invalid_signature {\n        true'),
             ('version','engine.block_version() < 16','false'),
             ('base-gas','const BASE_GAS: i64 = 50_000;','const BASE_GAS: i64 = 49_999;'),
             ('canonical-chunk','(refs != 0 && size != CHUNK_BYTES)','(false)'),
             ('preactivation-gas','engine.block_version() >= 4','false')]
    build=['cargo','build','--manifest-path',str(ROOT/'tosctl/src/Cargo.toml'),'--locked','--release','-p','tos_vm','--example','pq-parity']
    exe=ROOT/'tosctl/src/target/release/examples/pq-parity'
    transcript=a.out.with_suffix('.tsv');reports=[]
    def execute():
        subprocess.run(build,cwd=ROOT,check=True)
        with transcript.open('w') as f:subprocess.run([str(exe),str(a.scenarios.resolve())],stdout=f,check=True)
    execute();check(a.scenarios,a.cpp,transcript)
    for name,before,after in mutants:
        if original.count(before)!=1:raise ValueError('guard must occur once: '+name)
        try:
            source.write_text(original.replace(before,after))
            execute() # Must compile and finish; a crash/error is not a kill.
            try:check(a.scenarios,a.cpp,transcript)
            except ValueError:reports.append({'guard':name,'killed':True})
            else:raise RuntimeError('surviving mutation: '+name)
        finally:source.write_text(original)
        execute();check(a.scenarios,a.cpp,transcript)
    a.out.write_text(json.dumps(reports,indent=2,sort_keys=True)+'\n')


if __name__=='__main__':main()
