#!/usr/bin/env python3
"""Use the pinned public corpus plus resource boundaries, not generated secrets."""
import argparse
from pathlib import Path
import sys
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT/'test/auth-extensions'))
from cells import Cell

def chain(raw):
    tail=None
    for i in reversed(range(0,len(raw),127)):
        c=Cell().raw(raw[i:i+127]);tail=c.ref(tail) if tail is not None else c
    return tail or Cell()

def main():
    p=argparse.ArgumentParser();p.add_argument('vectors',type=Path);p.add_argument('out',type=Path)
    p.add_argument('--program',action='append',default=[],metavar='NAME=PATH',
                   help='a compiled binding to execute instead of synthesized opcodes')
    a=p.parse_args()
    rows=[];good=None
    def add(name,cells,version=16,budget=1_000_000,ignore=0,repeats=1,expected='',program=None):
        fields=[name,str(version),str(budget),str(ignore),str(repeats),expected or '?']
        fields += [x if isinstance(x,str) else x.boc().hex() for x in cells]
        if program is not None:
            fields.append(program)
        rows.append('\t'.join(fields))
    for line in a.vectors.read_text().splitlines():
        ident,expected,*raw=line.split('\t');cs=[chain(bytes.fromhex(x)) for x in raw]
        add(ident,cs,expected=expected)
        if ident=='openssl-auth-commitment':good=cs
    if good is None: raise ValueError('missing independent positive control')
    add('version-15',good,version=15);add('version-0',good,version=0)
    add('eleven-paid-calls',good,repeats=11)
    for n in (0,9,10,33,34,50033,50034,54000,57000,60000): add('gas-'+str(n),good,budget=n)
    for i in range(4):
        cs=good.copy();cs[i]='int';add('wrong-type-'+str(i),cs)
        cs=good.copy();cs[i]='skip';add('underflow-'+str(i),cs)
    for which in range(4):
        cs=good.copy();cs[which]=Cell().uint(1,1);add('unaligned-'+str(which),cs)
        cs=good.copy();cs[which]=Cell().ref(Cell()).ref(Cell());add('two-refs-'+str(which),cs)
        cs=good.copy();cs[which]=Cell().ref(chain(b'x'));add('empty-prefix-'+str(which),cs)
    cs=good.copy();cs[2]=chain(bytes(2420));add('bad-signature-ignore-classic',cs,ignore=1)
    # All bytes unchanged: noncanonical partition must not be accepted.
    raw=bytearray();c=good[3]
    while True:
        raw.extend(int(c.bits or '0',2).to_bytes(len(c.bits)//8,'big'))
        if not c.refs:break
        c=c.refs[0]
    cs=good.copy();cs[3]=Cell().raw(raw[:126]).ref(chain(raw[126:]));add('canonical-partition',cs)
    # Error precedence and metering also belong to parity. Before v4 the VM
    # detects exhaustion after charging exception dispatch; v4+ checks earlier.
    for version in range(16):
        for budget in (0,9,10,59,60):
            expected = 'E-14' if budget < 60 else 'E6'
            add(f'preactivation-budget-{version}-{budget}',good,
                version=version,budget=budget,expected=expected)
    # The rows above run raw opcodes, which never reach the assembler. These run
    # the programs the shipped bindings actually compile to, on both VMs.
    for entry in a.program:
        name,_,path=entry.partition('=')
        code=Path(path).read_bytes().hex()
        add(f'{name}-binding',good,program=code,expected='V')
        cs=good.copy();cs[2]=chain(bytes(2420));add(f'{name}-binding-bad-signature',cs,program=code,expected='I')
        cs=good.copy();cs[3]=Cell().uint(1,1);add(f'{name}-binding-unaligned-key',cs,program=code,expected='M')
        add(f'{name}-binding-version-15',good,version=15,program=code,expected='E6')
        add(f'{name}-binding-out-of-gas',good,budget=50_033,program=code,expected='E-14')
    a.out.write_text('\n'.join(rows)+'\n');print(f'{len(rows)} scenarios')
if __name__=='__main__':main()
