#!/usr/bin/env python3
import copy,hashlib,json,re,struct,subprocess,sys,tempfile
from pathlib import Path
from jsonschema import Draft202012Validator,FormatChecker
ROOT=Path(__file__).resolve().parents[1];REPO=ROOT.parents[1]
formats=FormatChecker()
@formats.checks('uint64')
def uint64(v): return isinstance(v,str) and re.fullmatch(r'0|[1-9][0-9]{0,19}',v) is not None and int(v)<=2**64-1

def closed(v):
 if isinstance(v,dict):
  if v.get('type')=='object':
   assert v.get('additionalProperties') is False and set(v['required'])==set(v['properties'])
  for child in v.values():closed(child)
 elif isinstance(v,list):
  for child in v:closed(child)
def validator(name):return Draft202012Validator(json.loads((ROOT/'contracts'/name).read_text()),format_checker=formats)
def main():
 files=list((ROOT/'contracts').rglob('*.schema.json'))
 for p in files:
  s=json.loads(p.read_text());Draft202012Validator.check_schema(s);closed(s)
 native=json.loads((ROOT/'crates/health-core/tests/fixtures/native-core.json').read_text())
 validator('source-envelope.schema.json').validate(native)
 validator('edge-snapshot.schema.json').validate(dict(schema_version=1,status='partial',sources=[native],anchors=[]))
 assert native['payload']['pq_sign']['succeeded']=='9007199254740993'
 assert native['content_hash']==hashlib.sha256(json.dumps(native['payload'],sort_keys=True,separators=(',',':')).encode()).hexdigest()
 common=validator('common.schema.json');common.validate('18446744073709551615')
 for bad in ['18446744073709551616','01','１','-1',True,1.0,9007199254740993]:assert not common.is_valid(bad),bad
 run='00000000-0000-4000-8000-000000000001';start='2026-09-29T00:00:00Z';end='2026-09-29T00:01:00Z'
 fixtures={
 'tos_get_capabilities':{},
 'tos_get_node_snapshot':dict(node_id='v1',as_of=end,max_age_seconds=30,components=['process']),
 'tos_get_metric_window':dict(node_ids=['v1'],metric_ids=['rss_bytes'],scope_id='node',start=start,end=end,step_seconds=15,mode='series',max_points_per_series=4),
 'tos_get_event_window':dict(node_ids=['v1'],scope_id='node',start=start,end=end,sources=['collector'],kinds=['warning'],correlation_id='',contains='',limit=10,cursor=''),
 'tos_get_change_history':dict(node_ids=['v1'],start=start,end=end,kinds=['restart'],limit=10,cursor=''),
 'tos_get_block_evidence':dict(node_ids=['v1'],reference_id='blk_'+'a'*16,ancestor_depth=0,max_events=10)}
 for name,args in fixtures.items():
  value=dict(run_id=run,**args);v=validator('tools/'+name+'.input.schema.json');v.validate(value)
  assert not v.is_valid(dict(value,force_refresh=True))
  bad=copy.deepcopy(value);bad['run_id']='not-a-uuid';assert not v.is_valid(bad)
  for k in ['start','end','as_of']:
   if k in value:
    bad=copy.deepcopy(value);bad[k]=bad[k].replace('Z','+00:00');assert not v.is_valid(bad)
  output=dict(schema_version=1,request_id='fixture',run_id=run,network_id='a'*64,generated_at=end,status='unavailable',data=None,evidence=[],missing_evidence=[dict(source_id='native',reason='not collected')],coverage=dict(status='unknown',missing_fields=['native'],gaps=[],sampling_policy='none'),pagination=dict(next_cursor=None,truncated=False,scan_complete=False),error=dict(code='CACHE_MISS',message='not collected',retryable=False,retry_after_seconds=None),budget=dict(remaining_calls=15,remaining_bytes=130000,expires_at=end))
  ov=validator('tools/'+name+'.output.schema.json');ov.validate(output)
  bad=copy.deepcopy(output);bad['budget']['fake']=True;assert not ov.is_valid(bad)
  bad=copy.deepcopy(output);bad['data']={'anything':'not a typed DTO'};assert not ov.is_valid(bad)
 for name in ['development-fixture.yaml','production.example.yaml']:
  value=json.loads((ROOT/'config'/name).read_text());validator('config.schema.json').validate(value)
 production=json.loads((ROOT/'config/production.example.yaml').read_text())
 missing=[k for k,v in production.items() if v is None];assert len(missing)>=8
 catalog=json.loads((ROOT/'contracts/source-manifest.json').read_text())
 for source in catalog['sources']:
  a=source['anchor'];raw=subprocess.check_output(['git','show',a['commit']+':'+a['path']],cwd=REPO)
  assert a['symbol'] in raw.decode() and hashlib.sha256(raw).hexdigest()==a['source_sha256']
  if source['fixture'] is None:assert not source['capability']['contract_valid']
 frozen=(ROOT/'tests/fixtures/diagnostic-v1.hex').read_text().strip()
 wire=struct.pack('<4sHHHHI16sQQQHHI',b'THD1',1,64,66,1,7,b'\x11'*16,9,10,0,2,0,0)+b'\x01\x02';assert wire.hex()==frozen
 with tempfile.TemporaryDirectory() as tmp:
  exe=Path(tmp)/'wire'
  subprocess.run(['c++','-std=c++17','-Wall','-Wextra','-Werror','-I',str(REPO),str(ROOT/'tests/native/diagnostic-wire.cpp'),'-o',str(exe)],check=True)
  assert subprocess.check_output([str(exe)],text=True).strip()==frozen
 print(f'PASS: {len(files)} closed schemas; six tool input/output fixtures; exact u64; source anchors; Python/C++ frozen IPC; production placeholders rejected')
if __name__=='__main__':main()
