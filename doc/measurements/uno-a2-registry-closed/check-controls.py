import ast,hashlib,json,shutil
from pathlib import Path
R=Path(__file__).resolve().parent
raw=(R/'wrapper.py').read_bytes()
tree=ast.parse(raw)
fn=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='classify')
namespace={'ROOT':R,'Path':Path,'json':json,'GATE':'cannot execute configured workchain: multi-account admission and replay are not connected'}
exec(compile(ast.Module(body=[fn],type_ignores=[]),str(R/'wrapper.py'),'exec'),namespace)
classify=namespace['classify']
out=R/'observation-controls';out.mkdir()
base=R/'fixture/account_binding_refused.result'
trace=R/'gate.trace.json'
assert classify(base,trace)=='account_readiness'
assert classify(R/'earlier.result',R/'earlier.trace.json')=='earlier_configuration_failure'
results=[]
for name in ['registry','account_variant','account_refusal','downstream_collator','downstream_validator_config','downstream_validator_ready','downstream_validator_transactions','delivery','typed_kind','typed_code','typed_message']:
    d=out/name;d.mkdir()
    p=d/'result'
    for suffix in ('','.kind','.message','.stats'):
        shutil.copyfile(Path(str(base)+suffix),Path(str(p)+suffix))
    obj=json.loads(trace.read_text())
    if name in obj['counts']:
        obj['counts'][name]=0 if not name.startswith('downstream_') else 1
    elif name=='delivery':
        s=Path(str(p)+'.stats');s.write_text(s.read_text().replace('delivery=recorded','delivery=unconfirmed'))
    elif name=='typed_kind': Path(str(p)+'.kind').write_text('ok\n')
    elif name=='typed_code': p.write_text('collate -7200\n')
    elif name=='typed_message': Path(str(p)+'.message').write_text('unknown local fault')
    t=d/'trace.json';t.write_text(json.dumps(obj,indent=2))
    try: classify(p,t)
    except ValueError as e: results.append({'name':name,'failure':str(e)})
    else: raise AssertionError('changed observation accepted: '+name)
assert classify(base,trace)=='account_readiness'
(R/'observation-controls.json').write_text(json.dumps({'scope':'Observation corruption controls, not production source mutations. Original raw sidecars never edited.','classifier_source_sha256':hashlib.sha256(raw).hexdigest(),'controls':results,'restored_original_still_passes':True},indent=2))
print(len(results),'controls rejected; originals still pass')
