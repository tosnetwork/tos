"""Hold the external-message provenance debt at the size it was measured.

Every path that submits an external message supplies a source today: both
overlays pass the broadcasting peer, the ADNL paths pass the querying node, and
the JSON-RPC submissions derive a stable per-client identity. What remains is
not a measured hole but a type: the source is an optional, so absence is
representable, and absence reaches the per-source limiter as the unlimited case
because that is what it has always meant.

Replacing the optional with a remote-or-local sum type is the fix. It cannot be
done yet, because the type is named in two files inside the frozen production
boundary. Until the change that reopens them, this keeps the debt closed: the
argument has no default, so provenance cannot be omitted, and the places that
still say "nothing" are the ones recorded here and cannot become more.

Shrinking any number below is fine and needs no edit here. Growing one, or
adding a file, is refused.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SEARCH = ('validator', 'validator-engine', 'test', 'create-hardfork', 'utils', 'lite-client')
SUFFIXES = {'.h', '.hpp', '.cpp'}

# A declared ingress source. The count is per file because a file may carry the
# interface, the override and the definition.
SURFACE = {
    'validator/validator.h': 2,
    'validator/manager.hpp': 3,
    'validator/manager.cpp': 4,
    'validator/manager-disk.hpp': 1,
    'validator/manager-disk.cpp': 1,
    'validator/manager-hardfork.hpp': 1,
    'validator/manager-hardfork.cpp': 1,
    'validator/impl/ext-message-pool.hpp': 1,
    'validator/impl/ext-message-pool.cpp': 1,
    'validator/impl/liteserver.hpp': 3,
    'validator/impl/liteserver.cpp': 2,
    'validator/fabric.h': 1,
    'validator/impl/fabric.cpp': 1,
}

# A call site that says "no remote identity" in so many words. Each is a local
# harness or tool submitting in process, which is why it is allowed to say it.
# It is provenance, not permission: none of these is exempt from anything.
EMPTY_CALLS = {
    'create-hardfork/create-hardfork.cpp': 1,
    'test/test-tos-collator.cpp': 1,
    'test/test-ext-message-pool.cpp': 1,
}

DEFAULTED = re.compile(r'source_peer\s*=\s*\{\s*\}')
DECLARED = re.compile(r'optional\s*<\s*(?:tos::|ton::)?PublicKeyHash\s*>\s*source_peer')
EMPTY = re.compile(r'optional\s*<\s*(?:tos::|ton::)?PublicKeyHash\s*>\s*\{\s*\}')
ENTRY = re.compile(r'(?:new_external_message_broadcast|new_external_message_query|check_add_external_message)')


def sources() -> dict[str, str]:
    found = {}
    for top in SEARCH:
        base = ROOT/top
        if not base.is_dir():
            continue
        for path in base.rglob('*'):
            if path.suffix in SUFFIXES and path.is_file() and 'build' not in path.parts:
                found[str(path.relative_to(ROOT))] = path.read_text(errors='replace')
    return found


def counted(files: dict[str, str], pattern: re.Pattern) -> dict[str, int]:
    return {name: len(pattern.findall(text)) for name, text in files.items() if pattern.search(text)}


def nullopt_arguments(files: dict[str, str]) -> list[str]:
    """An entry point handed nullopt rather than a stated absence.

    Absence is already representable; what this refuses is a second spelling of
    it, because two spellings are how a rule gets enforced on one of them.
    """
    out = []
    for name, text in files.items():
        for match in ENTRY.finditer(text):
            if 'nullopt' in text[match.end():match.end()+200]:
                out.append(name)
                break
    return out


def errors_for(files: dict[str, str]) -> list[str]:
    errors = []
    for name, text in sorted(files.items()):
        if DEFAULTED.search(text):
            errors.append('an ingress source parameter has a default again: '+name)

    for label, pattern, recorded in (('declares an ingress source', DECLARED, SURFACE),
                                     ('states an absent source', EMPTY, EMPTY_CALLS)):
        actual = counted(files, pattern)
        for name, count in sorted(actual.items()):
            allowed = recorded.get(name, 0)
            if count > allowed:
                errors.append(f'{name} {label} {count} times; {allowed} recorded'
                              if allowed else f'{name} newly {label}')

    for name in sorted(nullopt_arguments(files)):
        errors.append('an ingress entry point is handed nullopt: '+name)
    return errors


def require_refused(name: str, files: dict[str, str]) -> list[str]:
    found = errors_for(files)
    if found:
        print(f'MUTATION_KILLED {name}: {found[0]}')
        return []
    return ['mutation survived: '+name]


def main() -> int:
    files = sources()
    errors = errors_for(files)

    victim = 'validator/validator.h'
    if victim not in files:
        errors.append('cannot locate the ingress interface')
    else:
        errors += require_refused('default-restored', {
            **files, victim: files[victim].replace('td::optional<PublicKeyHash> source_peer)',
                                                   'td::optional<PublicKeyHash> source_peer = {})', 1)})
        errors += require_refused('new-optional-source-surface', {
            **files, 'validator/invented-ingress.h': 'td::optional<PublicKeyHash> source_peer;\n'})
        errors += require_refused('new-absent-source-call-site', {
            **files, 'validator/invented-caller.cpp': 'f(td::optional<PublicKeyHash>{});\n'})
        errors += require_refused('nullopt-handed-to-an-entry-point', {
            **files, 'validator/invented-nullopt.cpp': 'new_external_message_broadcast(data, 0, std::nullopt);\n'})

    if errors:
        for error in errors:
            print('FAIL: '+error, file=sys.stderr)
        return 1
    print(f'PASS: provenance is mandatory; {sum(EMPTY_CALLS.values())} recorded absent-source call sites, '
          f'{sum(SURFACE.values())} recorded optional-source declarations')
    return 0


if __name__ == '__main__':
    sys.exit(main())
