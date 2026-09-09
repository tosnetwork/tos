import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import subprocess

def git(root, *args, data=None, allowed=(0,)):
    p=subprocess.run(['git','-C',str(root),*args],input=data,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    if p.returncode not in allowed:
        raise RuntimeError(p.stderr.decode())
    return p.stdout

def ignored(root, paths):
    if not paths: return {}
    result=git(root,'check-ignore','--no-index','-v','-z','--stdin',data=b'\0'.join(x.encode() for x in sorted(paths))+b'\0',allowed=(0,1))
    fields=result.split(b'\0')
    if fields[-1]==b'': fields.pop()
    assert len(fields)%4==0
    return {fields[i+3].decode(): {'source':fields[i].decode(),'line':fields[i+1].decode(),'pattern':fields[i+2].decode()} for i in range(0,len(fields),4)}

records=[]
for folder in ['/home/tomi/tos','/home/tomi/tos-m2']:
    root=Path(folder)
    tracked={p.decode() for p in git(root,'ls-files','-z').split(b'\0') if p}
    evidence={p for p in tracked if p.startswith('doc/measurements/') or ('evidence' in p.lower() and p.startswith(('doc/','uno/')))}
    reports={p for p in tracked if p.startswith(('doc/','uno/')) and Path(p).suffix in {'.md','.json'}}
    references={}
    excluded_external=0
    for name in sorted(reports):
        path=root/name
        if not path.is_file(): continue
        text=path.read_text(errors='surrogateescape')
        values=re.findall(r'(?:doc/measurements/|measurements/)[A-Za-z0-9_./+%-]+',text)
        values += re.findall(r'[`"\']([^`"\'\n]+\.(?:json|log|txt|csv|boc|bin|md))[`"\']',text)
        for value in values:
            if value.startswith(('/tmp/','/home/','http:','https:')):
                excluded_external+=1
                continue
            if not re.fullmatch(r'[A-Za-z0-9_./+%-]+',value) or '..' in PurePosixPath(value).parts: continue
            value=value.rstrip('./')
            # A repository-root source filename quoted in an evidence report
            # is not a child artifact under a directory inferred from its stem.
            if value in tracked and not value.startswith('doc/measurements/'):
                continue
            if value.startswith('doc/measurements/'):
                candidates=[value]
            elif value.startswith('measurements/'):
                candidates=['doc/'+value]
            else:
                candidates=[str(PurePosixPath(name).parent/value)]
                if name.startswith('doc/measurements/'):
                    candidates.append(str(PurePosixPath(name).parent/Path(name).stem/value))
            for candidate in candidates:
                if not candidate.startswith('doc/measurements/'): continue
                references.setdefault(candidate,set()).add(name)
    matching=ignored(root,evidence|set(references))
    local_ignored=[p.decode() for p in git(root,'ls-files','--others','--ignored','--exclude-standard','-z','--','doc/measurements').split(b'\0') if p]
    missing={p:{'rule':rule,'referenced_by':sorted(references[p]),'exists_locally':(root/p).exists()}
             for p,rule in matching.items() if p in references and p not in tracked}
    records.append({'root':folder,'head':git(root,'rev-parse','HEAD').decode().strip(),
                    'tracked_evidence_count':len(evidence),'tracked_evidence_paths':sorted(evidence),
                    'report_count':len(reports),'literal_reference_count':len(references),
                    'references':{p:sorted(names) for p,names in sorted(references.items())},
                    'tracked_matching_ignore':{p:r for p,r in matching.items() if p in tracked},
                    'referenced_ignored_untracked':missing,'local_ignored_evidence':local_ignored,
                    'external_scratch_references_excluded':excluded_external,
                    'ignore_sha256':hashlib.sha256((root/'.gitignore').read_bytes()).hexdigest()})
out=Path('/tmp/uno-evidence-ignore-audit-20260909.json')
out.write_text(json.dumps({'scope':'Indexed evidence and literal report references in both worktrees; external scratch paths excluded; dynamic/template references not claimed resolved', 'trees':records},indent=2)+'\n')
for r in records:
    print(json.dumps({k:r[k] for k in ['root','head','tracked_evidence_count','report_count','literal_reference_count','tracked_matching_ignore','referenced_ignored_untracked','local_ignored_evidence']},indent=2))
