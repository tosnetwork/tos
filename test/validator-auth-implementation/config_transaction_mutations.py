"""Remove one guard of the config-transaction assembler at a time.

A guard whose removal breaks no named case is a guard nothing depends on. Each
mutation must compile, reach the file, and fail its own named case for the
reason it was written for.
"""
import argparse,json,subprocess,sys
from pathlib import Path
SOURCE=Path("validator/auth/native-config-transaction.cpp")
BINARY=Path("build-p0/test/validator-auth-implementation/test-p0-config-transaction")
MUTATIONS=[
 ("exact-successor","coordinate-must-be-immediate-successor",
  '  if (inputs.parent.seqno_ == std::numeric_limits<std::uint32_t>::max() ||\n'
  '      inputs.inclusion != inputs.parent.seqno_ + 1)\n'
  '    return Error{"native-config-transaction-coordinate"};',
  '  if (inputs.inclusion <= inputs.parent.seqno_)\n'
  '    return Error{"native-config-transaction-coordinate"};'),
 ("chain-established","unestablished-chain-refused",
  '  if (inputs.chain.genesis_root == Hash{} || inputs.chain.genesis_file == Hash{} ||\n'
  '      inputs.chain.chain_domain == Hash{} || inputs.chain.network == 0)\n'
  '    return Error{"native-config-transaction-chain"};',''),
 ("history-owned","history-owned-for-authority-lifetime",
  '    , history_(std::move(history))',
  '    , history_(std::shared_ptr<const FinalizedAnchorSource>(history.get(), [](const FinalizedAnchorSource*) {}))'),
]
def build():
 return subprocess.run(["cmake","--build","build-p0","--target","test-p0-config-transaction","-j48"],capture_output=True,text=True,check=False).returncode==0
def run(owner):
 return subprocess.run([str(BINARY),"verify",str(owner)],capture_output=True,text=True,check=False)
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument("--owner",type=Path,required=True);p.add_argument("--out",type=Path,required=True);a=p.parse_args();a.out.mkdir(parents=True,exist_ok=True)
 original=SOURCE.read_text();baseline=run(a.owner)
 if baseline.returncode!=0:print("BASELINE-NOT-PASSING");return 1
 cases=[line.split()[1] for line in baseline.stdout.splitlines() if line.startswith("CASE_PASS")]
 records=[];failures=0
 for guard,case,before,after in MUTATIONS:
  if original.count(before)!=1:print(f"ANCHOR-NOT-UNIQUE {guard} ({original.count(before)})");failures+=1;continue
  SOURCE.write_text(original.replace(before,after,1));reached=before not in SOURCE.read_text();compiled=build();named=False;earlier=False
  if compiled:
   result=run(a.owner);output=result.stdout+result.stderr;named=result.returncode!=0 and case in output;earlier=all(f"CASE_PASS {name}" in output for name in cases[:cases.index(case)])
  SOURCE.write_text(original);restored=build() and run(a.owner).returncode==0
  record={"guard":guard,"case":case,"edit_reached_source":reached,"compiled":compiled,"named_assertion_failed":named,"no_earlier_case_failed":earlier,"restored_baseline":restored,"source_unchanged":SOURCE.read_text()==original};records.append(record);print(json.dumps(record))
  if not all(v for k,v in record.items() if k not in ("guard","case")):failures+=1
 (a.out/"mutations.json").write_text(json.dumps(records,indent=1));return 1 if failures else 0
if __name__=="__main__":sys.exit(main())
