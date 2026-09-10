#!/usr/bin/env python3
import copy, json, os, subprocess, sys
from pathlib import Path
ROOT=Path(__file__).resolve().parent
BIN=ROOT/'bin/test-tos-collator'
GATE='cannot execute configured workchain: multi-account admission and replay are not connected'
def classify(result, trace):
    # Strictly typed sidecars and dedicated sites, never console diagnostics.
    t=json.loads(trace.read_text())
    expected=set(json.loads((ROOT/'sites.json').read_text()))
    if t['errors'] or set(t['counts']) != expected:
        raise ValueError('missing/failed observation')
    c=t['counts']
    if any(type(v) is not int or v<0 for v in c.values()):
        raise ValueError('invalid counts')
    kind=Path(str(result)+'.kind').read_text()
    status=result.read_text()
    message=Path(str(result)+'.message').read_text()
    stats=Path(str(result)+'.stats').read_text()
    if kind!='error\n' or status!='collate -7201\n' or t['exit_code']!=2:
        raise ValueError('not expected typed local failure: '+repr((kind,status,message)))
    if 'delivery=recorded\n' not in stats or 'transactions=0\n' not in stats:
        raise ValueError('missing delivery or nonzero transactions')
    if any(c[k] for k in c if k.startswith('downstream_')):
        raise ValueError('downstream reached')
    if message==GATE and (c['registry'],c['account_variant'],c['account_refusal'])==(1,1,1):
        return 'account_readiness'
    if message=='cannot create block for configured workchain: configuration callback incorrectly classified a local failure as candidate invalid: injected account configuration fault' and all(c[k]==0 for k in ('registry','account_variant','account_refusal')):
        return 'earlier_configuration_failure'
    raise ValueError('unclassifiable: '+repr((status,message,c)))
def observed(args, label):
    trace=ROOT/(label+'.trace.json')
    cmd=['gdb','-q','-nx','--batch','--return-child-result','-x',str(ROOT/'observe.gdb'),'--args',str(BIN),*args]
    (ROOT/(label+'.argv.json')).write_text(json.dumps(cmd,indent=2))
    with (ROOT/(label+'.gdb.log')).open('xb') as f:
        r=subprocess.run(cmd,stdout=f,stderr=subprocess.STDOUT,env=dict(os.environ,A2_ROOT=str(ROOT),A2_TRACE=str(trace)),timeout=110)
    return r.returncode,trace
args=sys.argv[1:]
if '--query-result' not in args or Path(args[args.index('--query-result')+1]).name!='account_binding_refused.result':
    sys.exit(subprocess.run([str(BIN),*args]).returncode)
# A real earlier error is run and classified BEFORE the readiness measurement.
early=args.copy()
for flag,name in [('--query-result','earlier.result'),('--account-binding-probe','earlier.calls'),('--export-candidate','earlier.candidate')]:
    early[early.index(flag)+1]=str(ROOT/name)
early.append('--account-probe-config-failure')
rc,trace=observed(early,'earlier')
assert rc==2
answer=classify(ROOT/'earlier.result',trace)
assert answer=='earlier_configuration_failure',answer
assert (ROOT/'earlier.calls').read_text()=='config=1\nexecute=0\n'
assert not (ROOT/'earlier.candidate').exists()
# Silence and another local error cannot satisfy the same gate predicate.
negative=[]
for mode in ('missing_trace','missing_counts','wrong_message'):
    try:
        if mode=='missing_trace':
            classify(ROOT/'earlier.result',ROOT/'absent.trace.json')
        elif mode=='missing_counts':
            broken=json.loads(trace.read_text()); del broken['counts']['registry']
            p=ROOT/'missing-counts.trace.json';p.write_text(json.dumps(broken))
            classify(ROOT/'earlier.result',p)
        else:
            assert classify(ROOT/'earlier.result',trace)=='account_readiness','earlier failure is not the gate'
    except (ValueError,FileNotFoundError,AssertionError) as e:
        negative.append({'control':mode,'error':str(e)})
    else: raise AssertionError('calibration silently accepted '+mode)
(ROOT/'calibration.json').write_text(json.dumps({'actual':answer,'negative':negative,'completed_before_gate':True},indent=2))
rc,trace=observed(args,'gate')
result=Path(args[args.index('--query-result')+1])
assert classify(result,trace)=='account_readiness'
assert Path(args[args.index('--account-binding-probe')+1]).read_text()=='config=2\nexecute=0\n'
assert not Path(args[args.index('--export-candidate')+1]).exists()
(ROOT/'gate-check.json').write_text(json.dumps({'classification':'account_readiness','calibration_complete':True},indent=2))
# Preserve native output for the existing fixture driver, not as classification.
print((ROOT/'gate.gdb.log').read_text(errors='replace'))
sys.exit(rc)
