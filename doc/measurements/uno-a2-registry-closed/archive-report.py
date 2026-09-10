import hashlib,json,tarfile
from pathlib import Path
R=Path(__file__).resolve().parent
D=Path('/home/tomi/tos/doc/measurements/uno-a2-registry-closed')
report={'provenance':json.loads((R/'provenance.json').read_text()),'driver_exit':0,
 'scope':'Fresh passive collator measurement of shared registry refusal on the pinned merged tree. Not a live validator invocation, opening, or merged integration commit.',
 'calibration':json.loads((R/'calibration.json').read_text()),
 'gate_trace':json.loads((R/'gate.trace.json').read_text()),
 'earlier_trace':json.loads((R/'earlier.trace.json').read_text()),
 'observation_controls':json.loads((R/'observation-controls.json').read_text()),
 'typed_sidecars':{s:(R/('fixture/account_binding_refused.result'+s)).read_text() for s in ('','.kind','.message','.stats','.stats.timing','.binding')},
 'calls':(R/'fixture/calls.txt').read_text(),
 'candidate_export_exists':(R/'fixture/unexpected-candidate.bin').exists(),
 'post_run_binary_sha256':{str(p.relative_to(R)):hashlib.sha256(p.read_bytes()).hexdigest() for p in (R/'bin').iterdir()},
 'no_production_mutations':True,'explicit_rebuilds':'None: copied executables match the archived merged-tree build hashes before and after; no production source or executable was mutated.',
 'checkpoints':['setup-missing-include: dependency failure, no calibration','calibration-prefix-checkpoint: unknown exact prefix rejected; no gate measurement','stack-overhead-checkpoint: five layers observed, but timing assertion failed; not final driver acceptance'],
 'archive_sha256':hashlib.sha256((D/'raw-run.tar.gz').read_bytes()).hexdigest()}
with tarfile.open(D/'raw-run.tar.gz') as t:
    report['retained_files']={m.name:hashlib.sha256(t.extractfile(m).read()).hexdigest() for m in t.getmembers() if m.isfile()}
(D/'report.json').write_text(json.dumps(report,indent=2)+'\n')
print(len(report['retained_files']),'retained files')
