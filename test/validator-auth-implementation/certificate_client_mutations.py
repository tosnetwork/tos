"""Check private per-call proof reuse, exact response values and context binding."""
import argparse,json
from pathlib import Path
from certificate_proof_mutations import rust
SOURCE='validator-auth-native/src/certificate_proof.rs'
CASES=[
 ('claimed-weight',SOURCE,'if decode::<VerifyResult>(response)? != verified.result()? { return Err(Error("verified-result")); }',''),
 ('prepared-request-rebinding',SOURCE,'prepared.request_id != id ||',''),
 ('prepared-bytes-binding',SOURCE,'|| api_request_id(method, request)? != id',''),
 ('prepared-anchor-binding',SOURCE,'|| prepared.anchor != self.anchor',''),
 ('prepared-chain-binding',SOURCE,'|| prepared.chain != self.chain',''),
 ('prepared-duty-binding',SOURCE,'|| prepared.expected != self.expected',''),
 ('client-proof-chunks-once',SOURCE,'(13, Some(verified)) => {','(13, Some(_admitted)) => { let verified = verify_native_certificate_response(method, request, response, &self.anchor, &self.chain, &self.expected, reader)?;'),
]
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--fixtures',type=Path,required=True);p.add_argument('--out',type=Path,required=True);args=p.parse_args()
 report=rust(args,CASES,'certificate-client-conformance')
 args.out.write_text(json.dumps(dict(certificate_client_mutations=report,restored_baselines=True),indent=2)+'\n')
