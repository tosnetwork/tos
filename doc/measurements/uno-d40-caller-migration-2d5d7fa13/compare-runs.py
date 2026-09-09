import json,pathlib,re,shutil,xml.etree.ElementTree as E
out=pathlib.Path('/tmp/uno-d40-migration');rows=json.loads((out/'first-failure-analysis.json').read_text())
second={t.attrib['name']:t for t in E.parse(out/'final-regression.xml').findall('testcase')}
third={t.attrib['name']:t for t in E.parse(out/'admitted-six.xml').findall('testcase')}
for r in rows:
 t=second[r['name']];log=t.findtext('system-out','')
 if t.find('failure') is None:r['second_result']='Passed'
 else:
  assert 'retention/admission cap 16 reached' in log
  r['second_result']='Not run: fixture cap (CTest reports Failed)'
 if r['name'] in third:
  t=third[r['name']];log=t.findtext('system-out','');dest=out/'after-retention'/r['name'];dest.mkdir(parents=True,exist_ok=True);(dest/'ctest.log').write_text(log)
  r['after_retention_result']='Failed' if t.find('failure') is not None else 'Passed'
  match=re.search(r'(/tmp/uno-publication-build/counter-integration-[^/\s]+)',log)
  if match:
   src=pathlib.Path(match[1]);r['after_retention_fixture']=str(src)
   if not src.exists():
    assert t.find("failure") is None and "fixture passed and removed" in log
    r["successful_fixture_lifecycle"]="Existing test driver removed successful fixture; raw CTest output retained"
   for f in src.iterdir() if src.exists() else ():
    if f.is_file() and not f.is_symlink():shutil.copy2(f,dest/f.name)
  if t.find('failure') is not None:
   lines=(dest/'bootstrap.log').read_text().splitlines();r['after_retention_diagnostics']=[{'line':n,'text':re.sub(r'\x1b\[[0-9;]*m','',line)} for n,line in enumerate(lines,1) if 'invalid instance installation' in line]
 else:r['after_retention_result']='Not rerun in the six-case admission check'
 if r['category']=='fixture admission infrastructure':r['first_result']='Not run: fixture cap (CTest reports Failed)'
(out/'failure-comparison.json').write_text(json.dumps(rows,indent=2)+'\n')
lines=['# First-run failures: per-test comparison','','Raw CTest statuses are distinct from whether the application ran. Diagnostics below locate failures; they are not used as typed CandidateReject/LocalUnavailable acceptance assertions.','','| Test | First observation | Missing tool/environment explains it? | Second run | After retention migration |','| --- | --- | --- | --- | --- |']
for r in rows:lines.append('| '+ ' | '.join([r['name'],r['reason'],'Yes' if r['missing_tool_or_env_explains'] else 'No',r['second_result'],r['after_retention_result']])+' |')
lines+=['','The first run has six real bootstrap failures, six unexecuted application tests blocked by fixture admission, and one missing-environment failure. The second run does not explain or erase any of them. After moving retained directories, all six previously blocked tests executed: three passed; readiness failed with diagnostic 7406 and both activation tests failed during bootstrap with diagnostic 7409 (missing instance configuration). They did not establish the expected activation boundary.','', 'All full logs, numeric line references, retained fixture inputs and observed collate sidecars are indexed in failure-comparison.json.']
(out/'failure-comparison.md').write_text('\n'.join(lines)+'\n')
