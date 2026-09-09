"""Move completed private fixtures without deleting; require idle before rename."""
import hashlib,json,os,pathlib,re,subprocess,tempfile
root=pathlib.Path('/tmp/uno-publication-build');out=pathlib.Path('/tmp/uno-d40-migration')
report={'build':str(root),'operation':'rename only; no deletion','idle_scope':'process names plus all readable /proc cwd and fd links','permission_denied':[],'live_processes':[],'live_references':[]}
listing=subprocess.check_output(['ps','-eo','pid=,comm=,args='],text=True)
(out/'retention-processes.log').write_text(listing)
for line in listing.splitlines():
 fields=line.strip().split(None,2)
 if len(fields)<3 or int(fields[0]) in (os.getpid(),os.getppid()):continue
 if fields[1] in ('ctest','test-tos-collat','create-state') or (fields[1]=='cmake' and 'test-counter-disk-integration.cmake' in fields[2]):report['live_processes'].append(line)
report['read_links']=0;report['vanished_links']=0
for proc in pathlib.Path('/proc').iterdir():
 if not proc.name.isdigit():continue
 try:
  links=[proc/'cwd',*(proc/'fd').iterdir()]
  for link in links:
   try:target=os.readlink(link)
   except FileNotFoundError:report['vanished_links']+=1;continue
   report['read_links']+=1
   if target.startswith(str(root/'counter-integration-')):report['live_references'].append({'link':str(link),'target':target})
 except (FileNotFoundError,ProcessLookupError):pass
 except PermissionError:report['permission_denied'].append(str(proc))
report['pre_move_check']=True
(out/'retention-preflight.json').write_text(json.dumps(report,indent=2)+'\n')
assert not report['live_processes'] and not report['live_references'], 'Test host or fixture references are not idle; nothing moved'
items=sorted(p for p in root.iterdir() if re.fullmatch('counter-integration-[0-9a-f]{12}',p.name) and p.is_dir() and not p.is_symlink())
def manifest(path):
 h=hashlib.sha256();count=0
 for f in sorted(path.rglob('*')):
  if f.is_file() and not f.is_symlink():
   digest=hashlib.sha256(f.read_bytes()).digest();h.update(str(f.relative_to(path)).encode()+b'\0'+digest);count+=1
 return {'files':count,'sha256':h.hexdigest()}
archive=pathlib.Path(tempfile.mkdtemp(prefix='retained-d40-fixtures-',dir=root));report['archive']=str(archive);report['moved']=[]
for p in items:
 before=manifest(p);dst=archive/p.name;p.rename(dst);after=manifest(dst);assert before==after
 report['moved'].append({'from':str(p),'to':str(dst),'before':before,'after':after})
(out/'retention.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'archive':str(archive),'moved':len(items)}))
