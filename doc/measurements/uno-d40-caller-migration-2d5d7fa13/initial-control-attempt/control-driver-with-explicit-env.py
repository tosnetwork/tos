import hashlib,json,pathlib,subprocess,os,xml.etree.ElementTree as ET
root=pathlib.Path('/home/tomi/tos-m2');out=pathlib.Path('/tmp/uno-d40-migration');build='/tmp/uno-publication-build'
os.environ.update(FUNC_BIN=build+'/crypto/func', FIFT_BIN=build+'/crypto/fift', TOL_STDLIB=str(root/'crypto/smartcont/tol-stdlib'), CARGO_BUILD_JOBS='32')
def sha(b):return hashlib.sha256(b).hexdigest()
def run(name,cmd):
 with (out/(name+'.stdout.log')).open('wb') as o,(out/(name+'.stderr.log')).open('wb') as e:
  code=subprocess.run(cmd,cwd=root,stdout=o,stderr=e).returncode
 return {'command':cmd,'exit_code':code}
path='test/test-counter-disk-integration.cmake';p=root/path;original=p.read_bytes()
commit=subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip();blob=subprocess.check_output(['git','show',commit+':'+path],cwd=root)
assert original==blob
before=b'x{ff68187c}';after=b'x{6e1fa05f}';assert original.count(before)==1
mutant=original.replace(before,after);report={'commit':commit,'path':path,'git_blob_oid':subprocess.check_output(['git','rev-parse',commit+':'+path],cwd=root,text=True).strip(),'original_sha256':sha(original),'from':before.decode(),'to':after.decode(),'mutant_sha256':sha(mutant),'scope':'Executed Python/CTest source-tag comparison, failure identity 964. Not engine activation, identity admission, or a compiled application guard. The fixture is read as text; no binary embeds this mutation.'}
try:
 p.write_bytes(mutant)
 report['syntax']=run('mutant-syntax',['python3','-m','py_compile',str(root/'crypto/test/workchain-handwritten-tags.py')]);assert report['syntax']['exit_code']==0
 report['mutant_run']=run('tag-mutant',['ctest','--test-dir',build,'-R','^test-workchain-handwritten-tags$','--output-on-failure','--output-junit',str(out/'tag-mutant.xml')]);assert report['mutant_run']['exit_code']==8
 cases=ET.parse(out/'tag-mutant.xml').findall('.//testcase');assert len(cases)==1 and cases[0].find('failure') is not None and cases[0].find('skipped') is None
 assert '964: tag mismatch UnoV2EngineConfiguration' in (out/'tag-mutant.stdout.log').read_text()
finally:p.write_bytes(original)
report['restored_sha256']=sha(p.read_bytes());report['restore_audit_sha256']=sha(p.read_bytes().replace(before,after));assert report['restored_sha256']==sha(blob) and report['restore_audit_sha256']==sha(mutant)
report['execution_leaves']={'tag_check':['ctest','Python3: crypto/test/workchain-handwritten-tags.py'],'counter_driver':['cmake','base64','crypto/create-state','test-tos-collator'],'compiled_mutation_holders':[]}
report['explicit_restore_build']=run('restore-build',['cmake','--build',build,'--target','create-state','fift','test-tos-collator','test-workchain-block','-j32']);assert report['explicit_restore_build']['exit_code']==0
report['restored_run']=run('tag-restored',['ctest','--test-dir',build,'-R','^test-workchain-handwritten-tags$','--output-on-failure','--output-junit',str(out/'tag-restored.xml')]);assert report['restored_run']['exit_code']==0
(out/'control.json').write_text(json.dumps(report,indent=2)+'\n')
