#!/usr/bin/env python3
"""Run one isolated in-memory helper mutation at a time; emit raw evidence."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys

path = Path(__file__).with_name('workchain-activation-rejection.py').resolve()
source = path.read_text()
digest = lambda value: hashlib.sha256(value.encode()).hexdigest()
unknown = '''    raise UnclassifiableActivationStatus(
        f"unclassifiable activation status: boundary={boundary!r}, code={code!r}, message={message!r}"
    )'''
controls = [
    ('producer-uniqueness', 'if hits != [expected]:', 'if False:'),
    ('calibration-shape', "if len(rows) != 4 or any(len(row) != 5 for row in rows):", 'if False:'),
    ('calibration-flags', 'row[:2] != flags or ', ''),
    ('calibration-success', "if rows[3][:4] != ['1', '1', '0', '']:", 'if False:'),
    ('earlier-misclassified', '                return False', '                return True'),
    ('unknown-default-false', unknown, '    return False'),
    ('unknown-default-true', unknown, '    return True'),
    ('numeric-type-confusion', 'type(code) is int and isinstance(message, str)', 'True'),
    ('collator-prefix-drift', 'COLLATOR_PREFIX = "cannot create block for configured workchain: "',
     'COLLATOR_PREFIX = "unrecognized prefix: "'),
    ('producer-function-check',
     '''if f'return td::Status::Error("{ACTIVATION_MESSAGE}");' not in text[start:end]:''',
     'if False:'),
]
# Compile precisely the hashed text; the loader does not prepend source lines.
loader = "import sys; p=sys.argv[1]; sys.argv=[p,'-v']; globals()['__file__']=p; exec(compile(sys.stdin.read(),p,'exec'),globals())"
records = []
for name, before, after in controls:
    assert source.count(before) == 1, name
    offset = source.index(before)
    mutant = source[:offset] + after + source[offset + len(before):]
    restored = mutant[:offset] + before + mutant[offset + len(after):]
    assert restored == source and path.read_text() == source
    argv = [sys.executable, '-c', loader, str(path)]
    result = subprocess.run(argv, input=mutant, text=True, capture_output=True, timeout=60)
    assert result.returncode == 1 and 'FAIL:' in result.stderr and 'ERROR:' not in result.stderr, (name, result)
    records.append(dict(name=name, from_text=before, to_text=after, offset=offset,
                        base_sha256=digest(source), mutant_sha256=digest(mutant),
                        reconstructed_mutant_sha256=digest(source.replace(before, after)),
                        restored_sha256=digest(restored), disk_sha256=digest(path.read_text()),
                        argv=argv, exit_code=result.returncode, stdout=result.stdout, stderr=result.stderr))
result = subprocess.run([sys.executable, str(path), '-v'], text=True, capture_output=True, timeout=60)
assert result.returncode == 0 and path.read_text() == source, result
print(json.dumps(dict(method='Exact hashed mutant compiled in a fresh child; stdin is the mutant, no source prologue. Disk source never changed. Not production runtime evidence.',
                      source=str(path.relative_to(path.parents[2])), interpreter=sys.version,
                      controls=records, final=dict(sha256=digest(source), exit_code=result.returncode,
                                                  stdout=result.stdout, stderr=result.stderr)), indent=2))
