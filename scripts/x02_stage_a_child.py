#!/usr/bin/env python3
"""Fixed ordinary StageA bootstrap; no acquisition, shell or namespace changes."""
from __future__ import annotations

import argparse
import ctypes
import hashlib
import importlib.machinery
import json
import os
from pathlib import Path
import sys


def require(value, reason):
    if not value:
        raise ValueError(reason)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binding', required=True, type=Path)
    parser.add_argument('--binding-sha256', required=True)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    require(sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,
            'child requires isolated no-site no-bytecode interpreter')
    require(os.getresuid() == (1000, 1000, 1000)
            and os.getresgid() == (1000, 1000, 1000) and not os.getgroups(),
            'child ordinary identities/groups differ')
    libc = ctypes.CDLL(None, use_errno=True)
    # This bootstrap runs before any StageA import or thread, after plain exec.
    require(libc.prctl(47, 4, 0, 0, 0) == 0, 'clear ambient capabilities failed')
    class Header(ctypes.Structure):
        _fields_ = [('version', ctypes.c_uint32), ('pid', ctypes.c_int)]
    class Data(ctypes.Structure):
        _fields_ = [('effective', ctypes.c_uint32), ('permitted', ctypes.c_uint32),
                    ('inheritable', ctypes.c_uint32)]
    header, caps = Header(0x20080522, 0), (Data * 2)()
    require(libc.capset(ctypes.byref(header), ctypes.byref(caps)) == 0,
            'clear child effective/permitted/inheritable capabilities failed')
    status = Path('/proc/self/status').read_text()
    fields = dict(line.split(':', 1) for line in status.splitlines() if ':' in line)
    require(all(int(fields[key], 16) == 0 for key in
                ('CapEff', 'CapPrm', 'CapInh', 'CapAmb'))
            and int(fields['CapBnd'], 16) == 0x3000
            and int(fields['NoNewPrivs']) == 1, 'child capability/NNP verification failed')
    for fd in (3, 4):
        try:
            os.fstat(fd)
        except OSError:
            pass
        else:
            raise ValueError('queue descriptor leaked into StageA child')
    raw = args.binding.read_bytes()
    require(hashlib.sha256(raw).hexdigest() == args.binding_sha256,
            'child binding bytes changed')
    binding = json.loads(raw)
    from x02_four_node_binding import verify_binding
    verify_binding(binding)
    require(list(sys.version_info[:3]) == binding['python_version']
            and str(Path('/proc/self/exe').resolve()) == binding['interpreter'],
            'actual child interpreter/version differs from frozen closure')
    require(os.readlink('/proc/self/ns/net') == binding['private_netns']
            and binding['private_netns'] != binding['host_netns']
            and Path('/proc/self/cgroup').read_text() == binding['cgroup'],
            'child namespace/cgroup differs')
    receipt = {'pid': os.getpid(), 'stat': Path('/proc/self/stat').read_text(),
               'status': status, 'netns': os.readlink('/proc/self/ns/net'),
               'cgroup': Path('/proc/self/cgroup').read_text(), 'queue_fds_closed': True,
               'binding_sha256': args.binding_sha256,
               'interpreter': os.readlink('/proc/self/exe'), 'version': sys.version,
               'prefix': sys.prefix, 'base_prefix': sys.base_prefix,
               'sys_path_before_project_imports': sys.path}
    receipt['child_executed_sha256'] = __x02_child_sha256__
    receipt['binding_helper_executed_sha256'] = sys.modules['x02_four_node_binding'].__executed_sha256__
    with (args.output / 'child-bootstrap.json').open('x') as stream:
        json.dump(receipt, stream, sort_keys=True, indent=2)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())
    repo = Path(binding['source_root'])
    sys.path[:0] = [str(repo / 'scripts'), str(repo / 'test/tostester/src'),
                    *binding['dependency_roots']]
    # Force project/dependency loads from the indexed source instead of ignored
    # in-tree caches; -B prevents creating a new cache. Stdlib closure is pinned.
    sys.pycache_prefix = str(args.output / 'disabled-bytecode-cache')
    require(not Path(sys.pycache_prefix).exists(), 'unexpected child bytecode cache')
    origins = []
    def verified_bytes(path):
        path = str(Path(path).absolute())
        require(path in binding['files'], 'import origin is outside frozen closure: ' + path)
        raw = Path(path).read_bytes()
        expected = binding['files'][path]
        require(len(raw) == expected['bytes']
                and hashlib.sha256(raw).hexdigest() == expected['sha256'],
                'actual import bytes differ: ' + path)
        origins.append({'path': path, 'sha256': expected['sha256'], 'bytes': len(raw)})
        return raw
    class VerifiedSource(importlib.machinery.SourceFileLoader):
        def get_data(self, path):
            if path.endswith('.pyc'):
                raise OSError('source bytes required')
            return verified_bytes(path)
    class VerifiedExtension(importlib.machinery.ExtensionFileLoader):
        def create_module(self, spec):
            verified_bytes(self.path)
            return super().create_module(spec)
        def exec_module(self, module):
            super().exec_module(module)
            verified_bytes(self.path)
    hook = importlib.machinery.FileFinder.path_hook(
        (VerifiedSource, importlib.machinery.SOURCE_SUFFIXES),
        (VerifiedExtension, importlib.machinery.EXTENSION_SUFFIXES))
    sys.path_hooks[:] = [hook]
    sys.path_importer_cache.clear()
    path = repo / 'scripts/validator-election-stage-a.py'
    sys.argv = [str(path), *binding['stage_argv']]
    try:
        exec(compile(verified_bytes(path), str(path), 'exec'),
             {'__name__': '__main__', '__file__': str(path)})
    finally:
        with (args.output / 'child-import-origins.json').open('x') as stream:
            json.dump({'actual_verified_reads': origins, 'modules': {
                name: getattr(module, '__file__', None) for name, module in sys.modules.items()}},
                stream, sort_keys=True, indent=2)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())


if __name__ == '__main__':
    require('__x02_child_sha256__' in globals(), 'only the fixed verified bootstrap may enter')
    main()
