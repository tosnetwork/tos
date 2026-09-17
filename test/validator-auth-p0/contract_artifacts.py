"""Check/generate the schema view and noncircular profile artifact fingerprint."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[2]
DOC = ROOT/'doc/validator-auth-p0'
FREEZE = ROOT/'doc/validator-auth-p0-freeze.json'
GENERATOR = ROOT/'tools/validator-auth/generate.py'
START = '<!-- canonical-schema:begin -->'
END = '<!-- canonical-schema:end -->'


def duplicate_pairs(items):
    out = {}
    for key, value in items:
        if key in out:
            raise ValueError('duplicate schema member: '+key)
        out[key] = value
    return out


def inspect_schema():
    schema = json.loads((DOC/'canonical-schema.json').read_text(), object_pairs_hook=duplicate_pairs)
    if schema['schema_version'] != 1 or schema['version'] != 1 or schema['flags'] != 0:
        raise ValueError('unsupported schema version')
    tags = set(); types = schema['types']; seen = set()
    def check_type(t, ancestors):
        if t in ('u8', 'u16', 'u32', 'u64', 'i32', 'h'):
            return
        if re.fullmatch(r'b[1-9][0-9]*', t):
            if int(t[1:]) > schema['limits']['object_bytes']:
                raise ValueError('blob bound')
            return
        if t.startswith('l'):
            match = re.fullmatch(r'l(8|16|32)/([1-9][0-9]*)/(.+)', t)
            if not match or int(match[2]) >= 1 << int(match[1]):
                raise ValueError('list type')
            check_type(match[3], ancestors); return
        if t not in types or t in ancestors:
            raise ValueError('unknown or recursive type: '+t)
        if t in seen:
            return
        fields = types[t]['fields']
        if len({x[0] for x in fields}) != len(fields):
            raise ValueError('duplicate field')
        for name, child in fields:
            if not re.fullmatch('[a-z][a-z0-9_]*', name):
                raise ValueError('field name')
            check_type(child, ancestors | {t})
        seen.add(t)
    for name, definition in types.items():
        tag = definition['tag']
        if tag is not None:
            if not re.fullmatch('[A-Za-z0-9]{4}', tag) or tag in tags:
                raise ValueError('duplicate or invalid tag')
            tags.add(tag)
        check_type(name, set())
    if set(schema['methods']) != {str(i) for i in range(1, 16)}:
        raise ValueError('method inventory')
    paths = []
    for method in schema['methods'].values():
        if method['request'] not in types or method['result'] not in types:
            raise ValueError('method type')
        paths.append(method['path'])
    if len(set(paths)) != 15:
        raise ValueError('duplicate method path')
    return schema


def rendered(schema):
    rows = []
    for name, t in schema['types'].items():
        rows.append((name + (' '+t['tag'] if t['tag'] else '')+' = '+ ' '.join(n+':'+k for n,k in t['fields'])).rstrip())
    return START+'\n```text\n'+'\n'.join(rows)+'\n```\n'+END


def ledger_errors(artifacts, recorded, declared):
    """The bytes, the profile and the frozen record must say one thing.

    Two places record the digest of each normative artifact. They drifted once,
    each passing its own lock while naming different bytes. This requires all
    three to agree at once, so neither ledger can be updated alone.

    The frozen record's amendment chain is an audit trail and is deliberately
    not consulted here. A chain describing how an artifact reached its current
    bytes must not become a way to authorise a profile that still commits to
    the bytes it replaced: the profile is what the policy signs, so what it
    names has to be what is on disk now.
    """
    errors = []
    for name, digest in sorted(artifacts.items()):
        if recorded.get(name) != digest:
            errors.append('the profile does not name the current bytes of '+name)
        path = 'doc/validator-auth-p0/'+name
        if path not in declared:
            errors.append('the frozen record does not carry '+name)
        elif declared[path] != digest:
            errors.append('the frozen record does not name the current bytes of '+name)
    return errors


def require_ledger_mutation_refused(name, artifacts, recorded, declared):
    if ledger_errors(artifacts, recorded, declared):
        print('MUTATION_KILLED '+name)
        return []
    return ['ledger mutation survived: '+name]


def generator():
    """The tool that owns what the generated production files must contain.

    It is imported rather than run as a command so that this gate and the
    generator's own job perform one comparison rather than two descriptions of
    it. The generator stays the canonical checker; this only makes the earlier
    gate able to see it.
    """
    spec = importlib.util.spec_from_file_location('validator_auth_generate', GENERATOR)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def generated_errors():
    """Close the loop from the profile to the production files derived from it.

    The profile digest is embedded in generated C++ and Rust. Those files are
    deliberately not in the frozen artifact set: they are deterministic
    derivations, and generation freshness is a different constraint from
    historical byte preservation. What they need is to be inside the same gate
    as the ledgers, because a profile revision that updates the record and the
    vectors while leaving these stale used to pass every earlier check and fail
    only in a later job.
    """
    generate = generator()
    expected = generate.expected_outputs()
    errors = ['a generated file is not what the current schema and profile render: '+str(path.relative_to(ROOT))
              for path in generate.check_generated(expected=expected)]
    # Prove this gate reaches the generator rather than merely importing it.
    # One byte moved in any generated output has to be refused here.
    for target in sorted(expected, key=str):
        def moved(path, target=target):
            return expected[path]+'\n' if path == target else expected[path]
        if generate.check_generated(read=moved, expected=expected) == [target]:
            print('MUTATION_KILLED generated-output-moved: '+str(target.relative_to(ROOT)))
        else:
            errors.append('generated mutation survived: '+str(target.relative_to(ROOT)))
    return errors


def main(write=False):
    schema = inspect_schema()
    wire_path = DOC/'WIRE.md'; wire = wire_path.read_text()
    expected = rendered(schema)
    if START not in wire:
        a = wire.index('```text'); b = wire.index('```', a+3)+3
        updated = wire[:a]+expected+wire[b:]
    else:
        a = wire.index(START); b = wire.index(END)+len(END)
        updated = wire[:a]+expected+wire[b:]
    if write:
        wire_path.write_text(updated)
    elif updated != wire:
        raise ValueError('WIRE generated schema view drift')
    artifacts = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(DOC.iterdir())
                 if p.is_file() and p.name != 'profile.json'}
    profile_path = DOC/'profile.json'; profile = json.loads(profile_path.read_text())
    if write:
        profile['revision'] = 4
        profile['grammar'] = 'canonical-schema.json ordered field arrays; WIRE.md generated view'
        profile['operations']['cancel'] = 7
        profile['limits'].update(pending_per_identity=10, pending_per_role_profile=1, schedule_delay_mc_blocks=65536,
                                 api_binary_bytes=2000000, api_transport_bytes=4194304)
        profile['artifact_sha256'] = artifacts
        profile_path.write_text(json.dumps(profile, indent=2)+'\n')
    elif profile.get('artifact_sha256') != artifacts:
        raise ValueError('profile artifact fingerprint drift')
    if not write:
        recorded = profile.get('artifact_sha256', {})
        declared = json.loads(FREEZE.read_text())['artifact_sha256']
        errors = ledger_errors(artifacts, recorded, declared)
        # Prove the check speaks, on each ledger and on the bytes themselves.
        # One moved digest anywhere has to be refused, or the agreement this
        # asserts is an agreement nobody is checking.
        victim = sorted(artifacts)[0]
        elsewhere = '0'*64
        errors += require_ledger_mutation_refused('profile-ledger-moved-alone', artifacts,
                                                  {**recorded, victim: elsewhere}, declared)
        errors += require_ledger_mutation_refused('frozen-record-moved-alone', artifacts, recorded,
                                                  {**declared, 'doc/validator-auth-p0/'+victim: elsewhere})
        errors += require_ledger_mutation_refused('artifact-moved-without-either-ledger',
                                                  {**artifacts, victim: elsewhere}, recorded, declared)
        errors += generated_errors()
        if errors:
            for error in errors:
                print('FAIL: '+error, file=sys.stderr)
            raise ValueError('the profile, the frozen record and what is derived from them disagree')
    print('PASS: canonical schema, generated view, profile fingerprint, both ledgers agreeing '
          'and the generated production files current')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--write', action='store_true')
    main(parser.parse_args().write)
