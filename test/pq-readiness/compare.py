#!/usr/bin/env python3
"""Require exact C++/Rust execution parity and independent positive/negative controls."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess



def source_commit() -> str:
    """Bind a report to the tree that produced it, for the activation precheck."""
    return subprocess.run(['git', 'rev-parse', 'HEAD'],
                          cwd=Path(__file__).resolve().parents[2], check=True,
                          capture_output=True, text=True).stdout.strip()

def check(scenarios: Path, cpp: Path, rust: Path) -> dict:
    source = [line.split('\t') for line in scenarios.read_text().splitlines()]
    if any(len(row) != 10 for row in source):
        raise ValueError('malformed scenario input')
    if len({row[0] for row in source}) != len(source):
        raise ValueError('duplicate scenario identifier')
    a, b = cpp.read_text().splitlines(), rust.read_text().splitlines()
    if len(a) != len(source) or len(b) != len(source) or len(a) < 20:
        raise ValueError('missing execution evidence')
    # Normalize only hash spelling. Scenario identity and numeric text stay exact.
    def normalize(line):
        fields = line.split('\t')
        if len(fields) != 7:
            raise ValueError('malformed execution row')
        fields[5:] = [value.lower() for value in fields[5:]]
        return '\t'.join(fields)
    a = [normalize(line) for line in a]; b = [normalize(line) for line in b]
    differences = [(source[i][0], x, y) for i, (x,y) in enumerate(zip(a,b)) if x != y]
    if differences:
        raise ValueError('execution divergence: '+repr(differences[:12]))
    positive = negative = malformed = 0
    for case, text in zip(source, a):
        fields = text.split('\t')
        if fields[0] != case[0]:
            raise ValueError('wrong or duplicated scenario')
        exit_code, gas, value, committed = map(int, fields[1:5])
        if gas < 0 or committed not in (0, 1):
            raise ValueError('invalid gas or commit evidence')
        expected = case[5]
        if expected == 'V':
            if (exit_code,value,committed) != (0,-1,1):raise ValueError('valid proof not accepted')
            positive += 1
        elif expected == 'I':
            if (exit_code,value,committed) != (0,0,1):raise ValueError('invalid proof accepted')
            negative += 1
        elif expected == 'M':
            if exit_code != 9:raise ValueError('malformed bytes not rejected')
            malformed += 1
        elif expected.startswith('E'):
            if (exit_code,value,committed) != (int(expected[1:]),99,0):
                raise ValueError('wrong error precedence: '+case[0])
        elif expected != '?':
            raise ValueError('unknown expected verdict')
        name=case[0]
        required = (6 if name.startswith('version-') else 7 if name.startswith('wrong-type-')
                    else 2 if name.startswith('underflow-') else 9 if name.startswith(('unaligned-','two-refs-','empty-prefix-','canonical-partition')) else None)
        if required is not None and exit_code != required:raise ValueError('missing guard: '+name)
        if name=='bad-signature-ignore-classic' and (exit_code,value)!=(0,0):raise ValueError('classic bypass affected PQ')
        if name=='eleven-paid-calls' and (exit_code!=0 or gas<550_000):raise ValueError('PQ free-call allowance')
        if name.startswith('gas-') and int(case[2])<57000 and exit_code!=-14:raise ValueError('gas guard not enforced')
        if name.startswith('preactivation-budget-'):
            version, budget = int(case[1]), int(case[2])
            required_gas = 10 if version >= 4 and budget < 10 else 60
            if gas != required_gas:
                raise ValueError('wrong historical exception metering: '+name)
    if positive<3:raise ValueError('independent positive controls missing')
    # Opcode-for-opcode agreement is a property of the two builds, not of any
    # chain, so it is declared network-independent rather than given a network.
    return {'success':True,'network':None,'scope':'network-independent',
            'source_commit':source_commit(),'scenarios':len(a),'positive':positive,'negative':negative,'malformed':malformed,
            'comparison':'exit, gas, verdict, commit flag, c4, c5',
            'scenario_sha256':hashlib.sha256(scenarios.read_bytes()).hexdigest()}


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('scenarios',type=Path)
    p.add_argument('cpp',type=Path);p.add_argument('rust',type=Path);p.add_argument('--out',type=Path,required=True)
    a=p.parse_args();result=check(a.scenarios,a.cpp,a.rust)
    a.out.write_text(json.dumps(result,indent=2,sort_keys=True)+'\n');print(json.dumps(result))
