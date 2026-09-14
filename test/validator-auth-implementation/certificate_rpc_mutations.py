"""Require behavioral failures when native certificate RPC authority checks disappear."""
import argparse,json,subprocess
from pathlib import Path
from mutation_support import replace_once
CASES=[
 ('api-certificate-history','native-rpc','if (source_failure) return *source_failure;',''),
 ('api-certificate-missing-object','native-rpc','if (reader.source_error()) return *reader.source_error();',''),
 ('api-certificate-bad-proof','native-rpc','return Error{"api-bad-request"};','return Error{"backend-error"};'),
 ('api-certificate-context','native-rpc','if (error == "certificate-anchor" || error == "expected-context" || error == "certificate-chain-context") return Error{"api-context-mismatch"};',''),
 ('api-certificate-context','client-api-common','|| e == "api-context-mismatch"',''),
 ('api-certificate-missing-object','transfer','source_error_ = chunk.error();',''),
 ('object-source-reset','transfer','source_error_.reset();',''),
 ('rpc-object-no-source','transfer','source_error_ = Error{"object-unavailable"}; return *source_error_;','return Error{"object-unavailable"};'),
 ('rpc-router-chain','native-rpc','if (chain.value().network != network_) return Error{"certificate-chain-context"};',''),
 ('rpc-source-root','native-rpc','if (!std::equal(anchor.value().state_.begin(), anchor.value().state_.end(), hash.as_slice().ubegin())) return Error{"native-source-anchor"};',''),
 ('rpc-get-id','native-rpc','if (id.value() != q.value().certificate_id_) return Error{"certificate-id"};',''),
 ('rpc-get-chain','native-rpc','|| duty.value().genesis_root_ != chain.value().genesis_root',''),
 ('rpc-get-signatures','native-rpc','if (!verified.ok()) return verified.error(); auto proof = make_committee_proof','auto proof = make_committee_proof'),
 ('rpc-request-bound','native-rpc','if (request.size() > 2000000) return Error{"api-binary-bound"};',''),
 ('rpc-history-refusal','certificate-proof','auto resolved = resolve(cert.value().duty_);','Result<Duty> resolved = cert.value().duty_;'),
 ('rpc-independent-duty','certificate-proof','const auto& expected = resolved.value();','const auto& expected = cert.value().duty_;'),
]
def main(args):
 folder=args.build.resolve()/'test/validator-auth-implementation';report=[]
 for module in ('native-rpc','certificate-proof','api-service','transfer','client-api-common'):
  # The client classification lives in a header now, so its mutant copies the
  # header into a root that precedes the real one on the include path.
  source=(folder/'client-common-mutant/client-api-common.h'
          if module=='client-api-common' else folder/f'rpc-mutated-{module}.cpp')
  original=source.read_text()
  def run(text):
   source.write_text(text)
   built=subprocess.run(['cmake','--build',str(args.build.resolve()),'--target',f'test-p0-rpc-{module}-mutant','-j2'],capture_output=True,text=True)
   if built.returncode:raise RuntimeError(built.stdout+built.stderr)
   return subprocess.run([str(folder/f'test-p0-rpc-{module}-mutant'),str(args.states.resolve()),str(args.fixtures.resolve())],capture_output=True,text=True)
  result=run(original);assert result.returncode==0,result.stderr
  try:
   for label,part,before,after in CASES:
    if part!=module:continue
    result=run(replace_once(original,before,after))
    assert result.returncode==1 and result.stderr.strip()=='ASSERTION: '+label,(label,result.stderr)
    report.append(dict(guard=label,compiled=True,assertion_failed=True));print('KILLED:',label,flush=True)
  finally:
   result=run(original);assert result.returncode==0,result.stderr
 args.out.write_text(json.dumps(dict(certificate_rpc_mutations=report,restored_baselines=True),indent=2)+'\n')
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--build',type=Path,required=True);p.add_argument('--states',type=Path,required=True);p.add_argument('--fixtures',type=Path,required=True);p.add_argument('--out',type=Path,required=True);main(p.parse_args())
