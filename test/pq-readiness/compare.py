#!/usr/bin/env python3
"""Require exact C++/Rust execution parity and independent positive/negative controls."""
import argparse
import hashlib
import json
from pathlib import Path


def check(scenarios: Path, cpp: Path, rust: Path) -> dict:
    source = [line.split('\t') for line in scenarios.read_text().splitlines()]
    a, b = cpp.read_text().splitlines(), rust.read_text().splitlines()
    if len(a) != len(source) or len(b) != len(source) or len(a) < 20:
        raise ValueError('missing execution evidence')
    # Hex spelling is normalized only for hashes, never numeric results or gas.
    a = [line.lower() for line in a]; b = [line.lower() for line in b]
    differences = [(source[i][0], x, y) for i, (x,y) in enumerate(zip(a,b)) if x != y]
    if differences:
        raise ValueError('execution divergence: '+repr(differences[:12]))
    positive = negative = malformed = 0
    for case, text in zip(source, a):
        fields = text.split('\t')
        if len(fields) != 7 or fields[0] != case[0].lower():
            raise ValueError('wrong or duplicated scenario')
        exit_code, gas, value, committed = map(int, fields[1:5])
        expected = case[5]
        if expected == 'V':
            if (exit_code,value,committed) != (0,-1,1):raise ValueError('valid proof not accepted')
            positive += 1
        if expected == 'I':
            if (exit_code,value,committed) != (0,0,1):raise ValueError('invalid proof accepted')
            negative += 1
        if expected == 'M':
            if exit_code != 9:raise ValueError('malformed bytes not rejected')
            malformed += 1
        name=case[0]
        required = (6 if name.startswith('version-') else 7 if name.startswith('wrong-type-')
                    else 2 if name.startswith('underflow-') else 9 if name.startswith(('unaligned-','two-refs-','empty-prefix-','canonical-partition')) else None)
        if required is not None and exit_code != required:raise ValueError('missing guard: '+name)
        if name=='bad-signature-ignore-classic' and (exit_code,value)!=(0,0):raise ValueError('classic bypass affected PQ')
        if name=='eleven-paid-calls' and (exit_code!=0 or gas<550_000):raise ValueError('PQ free-call allowance')
        if name.startswith('gas-') and int(case[2])<57000 and exit_code!=-14:raise ValueError('gas guard not enforced')
    if positive<3:raise ValueError('independent positive controls missing')
    return {'success':True,'scenarios':len(a),'positive':positive,'negative':negative,'malformed':malformed,
            'comparison':'exit, gas, verdict, commit flag, c4, c5',
            'scenario_sha256':hashlib.sha256(scenarios.read_bytes()).hexdigest()}


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('scenarios',type=Path)
    p.add_argument('cpp',type=Path);p.add_argument('rust',type=Path);p.add_argument('--out',type=Path,required=True)
    a=p.parse_args();result=check(a.scenarios,a.cpp,a.rust)
    a.out.write_text(json.dumps(result,indent=2,sort_keys=True)+'\n');print(json.dumps(result))
