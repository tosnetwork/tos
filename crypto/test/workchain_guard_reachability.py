"""Static, repository-local source reachability for the UNO premise guards.

LIMIT: literal includes and Rust module declarations, not a compiler dependency
or call graph. Runtime coupling, aliases, macro-generated includes, indirect
references and separately linked translation units are not inferred. Such
translation units must be explicit roots. External libraries stop at their
include boundary. No directory is selected just because an identifier occurs.
"""
import json
from pathlib import Path, PurePosixPath
import posixpath
import re

# Native target include directories and its first-party dependencies. These
# resolve references; they do not select files for scanning.
INCLUDE_DIRS = ('', 'crypto', 'crypto/block', 'tdutils', 'tdactor', 'tddb', 'tdnet', 'tl', 'tl/generate')
# Generated build artifacts must resolve to their committed input, independent
# of whether somebody has built the C++ tree locally.
GENERATED = {
    'block/block-auto.h': 'crypto/block/block.tlb',
    'block-auto.h': 'crypto/block/block.tlb',
    'td/utils/config.h': 'tdutils/td/utils/config.h.in',
    'td/utils/git_info.h': 'tdutils/td/utils/git_info.h.in',
    'auto/tl/tos_api.h': 'tl/generate/scheme/tos_api.tl',
    'auto/tl/tos_api.hpp': 'tl/generate/scheme/tos_api.tl',
    'auto/tl/lite_api.h': 'tl/generate/scheme/lite_api.tl',
    'auto/tl/lite_api.hpp': 'tl/generate/scheme/lite_api.tl',
}
COMMENTS = re.compile(r'//[^\n]*|/\*[\s\S]*?\*/|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'')
INCLUDES = re.compile(r'^\s*#\s*include\s*([<"])([^>"\n]+)[>"]', re.M)
MODULES = re.compile(r'(?:#\[path\s*=\s*"([^"]+)"\]\s*)?(?:pub(?:\([^)]*\))?\s+)?mod\s+(\w+)\s*;')


def uncomment(source):
    return COMMENTS.sub(lambda m: '\n' * m.group().count('\n') if m.group().startswith(('//', '/*')) else m.group(), source)


class Sources:
    """Disk reader with optional isolated edits; edits never imply reachability."""
    def __init__(self, repo, edits=None):
        self.repo = Path(repo)
        self.edits = edits or {}

    def exists(self, name):
        return name in self.edits or (self.repo / name).is_file()

    def read(self, name):
        return self.edits[name] if name in self.edits else (self.repo / name).read_text()


def normalized(name):
    name = posixpath.normpath(name)
    if name.startswith('../') or name.startswith('/'):
        raise ValueError('reference leaves repository: ' + name)
    return name


def reach(sources, roots, limit, label, emit=False):
    pending = list(roots)
    found, external = {}, set()
    while pending:
        name = pending.pop()
        if name in found:
            continue
        if not sources.exists(name):
            raise ValueError('missing reachable source: ' + name)
        found[name] = sources.read(name)
        if len(found) > limit:
            if emit:
                print(json.dumps({'guard': label, 'entrypoints': list(roots),
                                  'reachable_count': len(found), 'limit': limit,
                                  'files': sorted(found), 'complete': False}))
            raise ValueError(f'{label}: reachable source count {len(found)} exceeds limit {limit}; inspect entrypoints')
        source = uncomment(found[name])
        for bracket, target in INCLUDES.findall(source):
            if target in GENERATED:
                pending.append(GENERATED[target])
                continue
            bases = ((str(PurePosixPath(name).parent),) if bracket == '"' else ()) + INCLUDE_DIRS
            resolved = next((n for base in bases if sources.exists(n := normalized(posixpath.join(base, target)))), None)
            if resolved is not None:
                pending.append(resolved)
            # Apple's platform SDK uses a quoted include in platform.h.
            elif bracket == '<' or target == 'TargetConditionals.h':
                external.add(target)
            else:
                raise ValueError(f'{name}: unresolved quoted include {target}')
        if name.endswith('.rs'):
            # Test-only external modules are not production entrypoints. All
            # other cfg branches are conservatively traversed, not evaluated.
            source = re.sub(r'#\[cfg\(test\)\]\s*(?:pub\s+)?mod\s+\w+\s*;', '', source)
            parent = PurePosixPath(name).parent
            module_base = parent if PurePosixPath(name).name in ('lib.rs', 'main.rs', 'mod.rs') else parent / PurePosixPath(name).stem
            for path, module in MODULES.findall(source):
                candidates = [str(parent / path)] if path else [str(module_base / (module + '.rs')), str(module_base / module / 'mod.rs')]
                matches = [normalized(n) for n in candidates if sources.exists(normalized(n))]
                if len(matches) != 1:
                    raise ValueError(f'{name}: cannot resolve Rust module {module}: {matches}')
                pending.extend(matches)
    if emit:
        print(json.dumps({'guard': label, 'entrypoints': list(roots), 'reachable_count': len(found),
                          'limit': limit, 'files': sorted(found), 'external_includes': sorted(external), 'complete': True}))
    return found


def controls(repo, roots, limit, label):
    """Use the same disk resolver and literal references as the normal scan."""
    source = Sources(repo)
    entry = next(p for p in roots if p.endswith(('.h', '.cpp')))
    original = source.read(entry)
    new = str(PurePosixPath(entry).parent / 'guard-reachable-control.h')
    edits = {entry: original + '\n#include "guard-reachable-control.h"\n',
             new: 'struct ReachabilityProbe {};\n'}
    if new not in reach(Sources(repo, edits), roots, limit, label):
        raise ValueError('literal new-file reference was not traversed')
    # Same source, disconnected: adding a disk file alone must not select it.
    if new in reach(Sources(repo, {new: edits[new]}), roots, limit, label):
        raise ValueError('unreferenced file entered the source set')
    if 'uno/crypto/src/lib.rs' in roots:
        rust_root = 'uno/crypto/src/lib.rs'
        rust_new = 'uno/crypto/src/guard_module_control.rs'
        edits = {rust_root: source.read(rust_root) + '\nmod guard_module_control;\n',
                 rust_new: 'pub struct RustModuleProbe;\n'}
        if rust_new not in reach(Sources(repo, edits), roots, limit, label):
            raise ValueError('Rust module reference was not traversed')
    # The upper bound must itself be observable. Use a chain of real includes,
    # not injected inventory entries, and insist on the size-specific failure.
    folder = str(PurePosixPath(entry).parent)
    edits = {entry: original + '\n#include "guard-size-0.h"\n'}
    for i in range(limit + 1):
        edits[f'{folder}/guard-size-{i}.h'] = (f'#include "guard-size-{i+1}.h"\n'
                                               if i < limit else '// end\n')
    try:
        reach(Sources(repo, edits), roots, limit, label)
    except ValueError as error:
        if 'exceeds limit' not in str(error):
            raise
    else:
        raise ValueError('reachable-set size limit was not enforced')
    print(f'{label}: source controls passed (connected/disconnected file, module if present, size limit)')
