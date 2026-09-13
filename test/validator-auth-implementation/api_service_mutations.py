"""Compile API admission/cache-boundary mutations against durable services."""
import argparse,json,subprocess,tempfile
from pathlib import Path
from mutation_support import replace_once
MUTATIONS=[
 ('api-principal-acl',None,'auto rule = access_.find(principal);','auto rule = access_.find(principal); if(rule==access_.end())rule=access_.begin();'),
 ('api-method-acl',None,'!(rule->second.methods & (std::uint16_t{1} << (route->method - 1)))','false'),
 ('api-private-state',None,'return failure(route->method, frame.request_id, 2, 4);','return failure(route->method, frame.request_id, 2, 0);'),
 ('api-identity-acl',2,'if (!allowed.ok())','if (false)'),
 ('api-prepare-acl',3,'if (!allowed.ok())','if (false)'),
 ('api-stage-acl',4,'if (!allowed.ok())','if (false)'),
 ('api-sign-acl',5,'if (!allowed.ok())','if (false)'),
 ('api-result-acl',6,'if (!allowed.ok())','if (false)'),
 ('api-retire-acl',7,'if (!allowed.ok())','if (false)'),
 ('api-stage-cached-chain',4,'if (!same_chain(chain_, q.value().permit_.body_))','if (false)'),
 ('api-retire-cached-chain',7,'if (!same_chain(chain_, q.value().permit_.body_))','if (false)'),
 ('api-sign-cached-chain',5,'if (duty.network_ != chain_.network || duty.genesis_root_ != chain_.genesis_root ||\n          duty.genesis_file_ != chain_.genesis_file)','if (false)'),
 ('api-result-cached-chain',6,'if (duty.network_ != chain_.network || duty.genesis_root_ != chain_.genesis_root ||\n            duty.genesis_file_ != chain_.genesis_file)','if (false)'),
 ('api-result-private-state',None,'return failure(frame.method, frame.request_id, 2, 4);','return failure(frame.method, frame.request_id, 2, 0);'),
 ('api-verb',None,'request.verb != route->verb','false'),
 ('api-request-media',None,'(route->method != 1 && request.content_type != api_media_type)','false'),
 ('api-capabilities-body',None,'(route->method == 1 && !request.body.empty())','false'),
]
def main(build,out):
 folder=build.resolve()/'test/validator-auth-implementation';source=folder/'mutated-api-service.cpp';original=source.read_text();report=[]
 def run(text):
  source.write_text(text)
  subprocess.run(['cmake','--build',str(build),'--target','test-p0-api-service-mutant','-j2'],check=True,capture_output=True,text=True)
  with tempfile.TemporaryDirectory(prefix='p0-api-mut-',dir='/tmp') as d:
   return subprocess.run([str(folder/'test-p0-api-service-mutant'),str(Path(d)/'data')],capture_output=True,text=True)
 base=run(original);assert base.returncode==0,base.stderr
 try:
  for name,method,before,after in MUTATIONS:
   if method is None:mutant=replace_once(original,before,after)
   else:
    start=original.index(f'    case {method}: {{');end=original.index(f'    case {method+1}: {{',start) if method<7 else original.index('    case 14: {',start)
    mutant=original[:start]+replace_once(original[start:end],before,after)+original[end:]
   result=run(mutant)
   assert result.returncode==1 and result.stderr.strip()=='ASSERTION: '+name,(name,'invalid kill',result.returncode,result.stderr)
   report.append(dict(guard=name,compiled=True,assertion_failed=True));print('KILLED:',name,flush=True)
 finally:
  base=run(original);assert base.returncode==0,base.stderr
 out.write_text(json.dumps(dict(api_service_mutations=report,restored_baselines=True),indent=2)+'\n')
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--build',type=Path,required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args();main(a.build,a.out)
