"""Hold external-message provenance total: a remote peer or a local origin.

The source used to be an optional peer. Absence was therefore representable,
and absence reached the per-source limiter as the case that is not limited at
all -- a meaning nobody chose, inherited from transports that had no identity
to hand over. Nothing made a new call site decide, so the way to get the
unlimited answer was to say nothing.

The type is now a sum of exactly two cases, so there is no third state to fall
through and no default to omit. This keeps it that way. What it refuses:

  an optional peer reappearing on the ingress path
  a default on a provenance parameter
  nullopt or an empty optional offered to an ingress entry point
  a limiter branch that answers without naming which case it answered for

The last one is why the visit is checked rather than trusted: a branch that
returns early for anything but the two named cases would restore the bypass
without restoring the type.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SEARCH = ('validator', 'validator-engine', 'test', 'create-hardfork', 'utils', 'lite-client')
SUFFIXES = {'.h', '.hpp', '.cpp'}

TYPE = ROOT/'validator/ext-message-ingress-source.h'
POOL = 'validator/impl/ext-message-pool.cpp'

# The ingress entry points. A provenance argument is mandatory at each.
ENTRY = re.compile(r'(?:new_external_message_broadcast|new_external_message_query|check_add_external_message)')
# An optional peer anywhere on the ingress path is the shape that was removed.
OPTIONAL_PEER = re.compile(r'optional\s*<\s*(?:tos::|ton::)?PublicKeyHash\s*>')
DEFAULTED = re.compile(r'(?:ExtMessageIngressSource|optional\s*<[^>]*PublicKeyHash[^>]*>)\s+\w+\s*=')


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


def errors_for(files: dict[str, str]) -> list[str]:
    errors = []
    for name, text in sorted(files.items()):
        for match in ENTRY.finditer(text):
            window = text[match.end():match.end()+240]
            if 'nullopt' in window:
                errors.append('an ingress entry point is handed nullopt: '+name)
                break
            if OPTIONAL_PEER.search(window):
                errors.append('an ingress entry point still takes an optional peer: '+name)
                break
        if OPTIONAL_PEER.search(text) and 'ExtMessageIngressSource' in text:
            errors.append('an optional peer survives beside the provenance type in: '+name)
        if DEFAULTED.search(text):
            errors.append('a provenance parameter has a default in: '+name)

    # The sum type must stay a sum of exactly the two named cases.
    declaration = files.get('validator/ext-message-ingress-source.h', '')
    if 'std::variant<RemotePeer, LocalOrigin>' not in declaration:
        errors.append('provenance is no longer a sum of a remote peer and a local origin')

    # And the limiter must answer for both of them by name.
    pool = files.get(POOL, '')
    if pool:
        for case in ('const RemotePeer &', 'const LocalOrigin &'):
            if case not in pool:
                errors.append('the limiter does not answer for '+case.strip()+' by name')
        if 'std::visit' not in pool:
            errors.append('the limiter no longer decides by visiting every case')
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

    pool = files.get(POOL, '')
    if not pool:
        errors.append('cannot locate the admission pool')
    else:
        errors += require_refused('optional-peer-returns-to-an-entry-point', {
            **files, 'validator/invented-ingress.cpp':
                'check_add_external_message(data, 0, false, td::optional<PublicKeyHash>{});\n'})
        errors += require_refused('nullopt-offered-to-an-entry-point', {
            **files, 'validator/invented-nullopt.cpp':
                'new_external_message_broadcast(data, 0, std::nullopt);\n'})
        errors += require_refused('provenance-parameter-given-a-default', {
            **files, 'validator/invented-default.h': 'void f(ExtMessageIngressSource source = {});\n'})
        errors += require_refused('local-case-no-longer-answered-by-name', {
            **files, POOL: pool.replace('const LocalOrigin &', 'const auto &', 1)})
        errors += require_refused('provenance-stops-being-a-sum-of-two', {
            **files, 'validator/ext-message-ingress-source.h':
                files.get('validator/ext-message-ingress-source.h', '').replace(
                    'std::variant<RemotePeer, LocalOrigin>', 'std::optional<RemotePeer>', 1)})

    if errors:
        for error in errors:
            print('FAIL: '+error, file=sys.stderr)
        return 1
    print('PASS: provenance is a remote peer or a local origin, with no third state, '
          'no default and no absent case reaching the limiter')
    return 0


if __name__ == '__main__':
    sys.exit(main())
