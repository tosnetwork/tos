#!/usr/bin/env python3
"""
Rename Grams -> Tomis across the TOS codebase.

Usage:
  # Dry-run on a test file:
  python3 scripts/rename-grams.py --test

  # Dry-run on the real codebase (shows what would change, no writes):
  python3 scripts/rename-grams.py --dry-run

  # Apply changes:
  python3 scripts/rename-grams.py --apply
"""

import argparse
import os
import re
import sys
from pathlib import Path

# ── Replacement rules ─────────────────────────────────────────────
#
# Each rule is (pattern, replacement, description).
# Patterns use word boundaries or exact context to avoid false positives.
# Order matters: longer/more specific patterns first.

RULES = [
    # === TL-B schema (block.tlb) ===
    (r'\bnanograms\b', 'nanotomis', 'TL-B type: nanograms -> nanotomis'),
    (r'\bNanograms\b', 'Nanotomis', 'TL-B type: Nanograms -> Nanotomis'),

    # === C++ auto-generated identifiers (from block.tlb) ===
    (r'\bt_Grams\b', 't_Tomis', 'TL-B C++ type object'),
    (r'\bt_Maybe_Grams\b', 't_Maybe_Tomis', 'TL-B C++ maybe type'),
    (r'\bblock_grams_created\b', 'block_tomis_created', 'auto-gen struct'),

    # === C++ hand-written methods ===
    (r'\bstore_grams\b', 'store_tomis', 'serialization method'),
    (r'\bstore_Maybe_Grams\b', 'store_Maybe_Tomis', 'serialization method'),
    (r'\bstore_Maybe_Grams_nz\b', 'store_Maybe_Tomis_nz', 'serialization method'),
    (r'\bload_grams\b', 'load_tomis', 'deserialization method'),
    (r'\bSTGRAMS\b', 'STTOMIS', 'TVM opcode name in Fift asm'),
    (r'\bLDGRAMS\b', 'LDTOMIS', 'TVM opcode name in Fift asm'),

    # === Struct fields ===
    (r'\.grams\b', '.tomis', 'struct field: .grams -> .tomis'),
    (r'_grams\b', '_tomis', 'variable suffix: _grams -> _tomis'),

    # === C++ variable names (whole word only) ===
    (r'\bgrams\b', 'tomis', 'variable/field name: grams -> tomis'),
    (r'\bGrams\b', 'Tomis', 'type/class name: Grams -> Tomis'),

    # === Fift syntax sugar ===
    (r'\bGram\*/', 'Tomi*/', 'Fift word: Gram*/ -> Tomi*/'),
    (r'\bGram\*\b', 'Tomi*', 'Fift word: Gram* -> Tomi*'),
    (r'\bGram,', 'Tomi,', 'Fift word: Gram, -> Tomi,'),
    (r'\bGram@\+', 'Tomi@+', 'Fift word: Gram@+ -> Tomi@+'),
    (r'\bGram@\b', 'Tomi@', 'Fift word: Gram@ -> Tomi@'),
    (r'\bGram\+cc,', 'Tomi+cc,', 'Fift word: Gram+cc, -> Tomi+cc,'),
    (r'\.GR_', '.TM_', 'Fift word: .GR_ -> .TM_'),
    (r'\.GR\+cc_', '.TM+cc_', 'Fift word: .GR+cc_ -> .TM+cc_'),
    (r'\.GR\+cc\b', '.TM+cc', 'Fift word: .GR+cc -> .TM+cc'),
    (r'\.GR\b', '.TM', 'Fift word: .GR -> .TM'),
    (r'\$>GR\?', '$>TM?', 'Fift word: $>GR? -> $>TM?'),
    (r'\$>GR\b', '$>TM', 'Fift word: $>GR -> $>TM'),
    (r'"GR\$"', '"TM$"', 'Fift display prefix string'),
    (r'GR\$', 'TM$', 'Fift amount prefix: GR$ -> TM$'),

    # === Fift constant ===
    (r'\bconstant Gram\b', 'constant Tomi', 'Fift constant: Gram -> Tomi'),
    # Bare "Gram" in Fift context (e.g. "{ Gram swap")
    (r'\bGram\b(?!\w)', 'Tomi', 'Fift reference to Gram constant'),

    # === Comments ===
    (r'\bGram amount\b', 'Tomi amount', 'comment text'),
    (r'\bnanoTOS\b', 'nanoTOS', 'already correct, skip'),
]

# ── Files to NEVER touch ──────────────────────────────────────────

EXCLUDE_DIRS = {'third-party', '.git', '.venv', 'build', 'node_modules'}
EXCLUDE_FILES = {'rename-grams.py'}

INCLUDE_EXTENSIONS = {'.cpp', '.h', '.hpp', '.fif', '.fc', '.tlb', '.py', '.md'}

# ── Words that must NEVER be modified ─────────────────────────────

PROTECTED_WORDS = {
    'Grammar', 'grammar', 'GRAMMAR',
    'Grampa', 'grampa',
    'datagram', 'datagrams', 'Datagram', 'Datagrams',
    'histogram', 'histograms', 'Histogram',
    'program', 'programs', 'Program', 'Programs',
    'diagram', 'diagrams', 'Diagram',
    'telegram', 'Telegram', 'TELEGRAM',
    'kilogram', 'kilograms',
    'instagram', 'Instagram',
    'pangram', 'epigram', 'monogram', 'pictogram',
    'anagram',
    'TolkLanguageGrammar',
    'ConcurrentMap_Grampa',
}


def should_process(path: Path) -> bool:
    for part in path.parts:
        if part in EXCLUDE_DIRS:
            return False
    if path.name in EXCLUDE_FILES:
        return False
    return path.suffix in INCLUDE_EXTENSIONS


def apply_rules(line: str) -> tuple[str, list[str]]:
    """Apply all replacement rules to a line. Returns (new_line, list_of_changes)."""
    changes = []
    result = line

    for pattern, replacement, desc in RULES:
        new_result = re.sub(pattern, replacement, result)
        if new_result != result:
            changes.append(desc)
            result = new_result

    # Safety check: verify no protected words were damaged
    for word in PROTECTED_WORDS:
        if word in line and word not in result:
            # A protected word was damaged! Revert this line.
            return line, [f'BLOCKED: would damage protected word "{word}"']

    return result, changes


def process_file(path: Path, dry_run: bool = True) -> dict:
    """Process a single file. Returns stats."""
    try:
        with open(path, 'r', encoding='utf-8', errors='replace') as f:
            lines = f.readlines()
    except Exception as e:
        return {'error': str(e)}

    new_lines = []
    file_changes = []
    blocked = []

    for i, line in enumerate(lines):
        new_line, changes = apply_rules(line)
        new_lines.append(new_line)
        for c in changes:
            if c.startswith('BLOCKED'):
                blocked.append((i + 1, c, line.rstrip()))
            elif new_line != line:
                file_changes.append((i + 1, c, line.rstrip(), new_line.rstrip()))

    if blocked:
        return {'blocked': blocked, 'changes': 0}

    if file_changes and not dry_run:
        with open(path, 'w', encoding='utf-8') as f:
            f.writelines(new_lines)

    return {'changes': file_changes}


# ── Test mode ─────────────────────────────────────────────────────

TEST_INPUT = r"""
// Safe replacements:
nanograms$_ amount:(VarUInteger 16) = Grams;
_ grams:Grams = Coins;
block::tlb::t_Grams.store_integer_value(cb, amount);
auto fee = msg.grams;
cb.store_grams(100);
auto x = cs.load_grams();
GR$1.7 GR$1 config.block_create_fees!
1000000000 constant Gram
{ Gram * } : Gram*
{ (.GR) ."GR$" type } : .GR_
{ $>GR? not abort"not a valid Gram amount" } : $>GR
balance_grams = total;
store_Maybe_Grams_nz(cb, value);
100000000 INT STGRAMS

// Must NOT change:
TolkLanguageGrammar grammar;
ConcurrentMap_Grampa map;
send datagram to peer;
this is a histogram of values;
running the program now;
// Telegram was renamed;
""".strip()

EXPECTED_SAFE = [
    'nanotomis',
    't_Tomis',
    '.tomis',
    'store_tomis',
    'load_tomis',
    'TM$1.7',
    'constant Tomi',
    'Tomi*',
    '.TM_',
    '$>TM',
    'balance_tomis',
    'store_Maybe_Tomis_nz',
    'STTOMIS',
]

EXPECTED_UNCHANGED = [
    'TolkLanguageGrammar',
    'ConcurrentMap_Grampa',
    'datagram',
    'histogram',
    'program',
    'Telegram',
]


def run_test():
    print("=" * 60)
    print("TESTING REPLACEMENT RULES")
    print("=" * 60)

    lines = TEST_INPUT.split('\n')
    all_ok = True

    print("\n--- Input -> Output ---\n")
    for i, line in enumerate(lines):
        new_line, changes = apply_rules(line)
        if new_line != line:
            print(f"  {i+1:3d} CHANGED: {line}")
            print(f"       =>    {new_line}")
            for c in changes:
                print(f"             ({c})")
        elif changes:
            print(f"  {i+1:3d} {changes[0]}: {line}")

    output = '\n'.join(apply_rules(line)[0] for line in lines)

    print("\n--- Safety checks ---\n")

    # Check expected replacements happened
    for expected in EXPECTED_SAFE:
        if expected in output:
            print(f"  ✓ Found expected: {expected}")
        else:
            print(f"  ✗ MISSING expected: {expected}")
            all_ok = False

    # Check protected words survived
    for protected in EXPECTED_UNCHANGED:
        if protected in output:
            print(f"  ✓ Protected survived: {protected}")
        else:
            print(f"  ✗ DAMAGED protected: {protected}")
            all_ok = False

    print()
    if all_ok:
        print("ALL TESTS PASSED ✓")
    else:
        print("SOME TESTS FAILED ✗")
    return all_ok


# ── Main ──────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description='Rename Grams -> Tomis')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--test', action='store_true', help='Run test cases')
    group.add_argument('--dry-run', action='store_true', help='Show changes without writing')
    group.add_argument('--apply', action='store_true', help='Apply changes to files')
    args = parser.parse_args()

    if args.test:
        ok = run_test()
        sys.exit(0 if ok else 1)

    repo_root = Path(__file__).resolve().parent.parent
    dry_run = not args.apply

    if dry_run:
        print("DRY RUN — no files will be modified.\n")
    else:
        print("APPLYING CHANGES.\n")

    total_files = 0
    total_changes = 0
    total_blocked = 0

    for root, dirs, files in os.walk(repo_root):
        dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]
        for fname in sorted(files):
            path = Path(root) / fname
            if not should_process(path):
                continue

            result = process_file(path, dry_run=dry_run)

            if 'error' in result:
                continue

            if 'blocked' in result:
                total_blocked += len(result['blocked'])
                for lineno, msg, line in result['blocked']:
                    rel = path.relative_to(repo_root)
                    print(f"  BLOCKED {rel}:{lineno} {msg}")
                    print(f"          {line}")
                continue

            changes = result.get('changes', [])
            if changes:
                total_files += 1
                total_changes += len(changes)
                rel = path.relative_to(repo_root)
                if dry_run:
                    for lineno, desc, old, new in changes:
                        print(f"  {rel}:{lineno} ({desc})")
                        print(f"    - {old}")
                        print(f"    + {new}")
                else:
                    print(f"  {rel}: {len(changes)} change(s)")

    print(f"\nTotal: {total_changes} changes in {total_files} files, {total_blocked} blocked")


if __name__ == '__main__':
    main()
