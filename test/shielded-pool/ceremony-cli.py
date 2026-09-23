#!/usr/bin/env python3
"""Run a whole phase-2 ceremony through the binaries, and require every refusal.

Building a binary is not running it, and the library's tests never touch the
binaries at all: they call `contribute` and `verify_chain` directly, with keys
they built in memory. Everything between -- reading a directory somebody else
wrote, refusing to begin over an existing ceremony, refusing to contribute
after the beacon, noticing a contribution that was altered on disk -- is code
no Rust test in this tree exercises.

So this drives the commands the way people will, then breaks the artifacts one
at a time and requires a refusal. A run takes about ten minutes, almost all of
it rebuilding the starting key from the committed slice: four commands do it,
which is the cost of each one checking rather than trusting.

Every secret here is the operating system's, drawn inside the library and
destroyed there. Nothing this script writes contains one.

Usage: ceremony-cli.py [--work <directory>] [--keep]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CRATE = ROOT / 'tools/shielded-pool-ceremony'
BINARIES = CRATE / 'target/release'

# Long enough to clear the floor the library enforces. A real beacon is a
# published value named before the ceremony opens; this one is text, and says
# so, because a script cannot supply the property that matters.
BEACON = b'a stand-in beacon output for this run, long enough to be accepted'
OTHER_BEACON = b'a different beacon output, also long enough to clear the floor!!'


def run(command: list[str], expect_success: bool = True) -> subprocess.CompletedProcess:
    started = time.monotonic()
    result = subprocess.run(command, capture_output=True, text=True)
    elapsed = time.monotonic() - started
    name = Path(command[0]).name
    if expect_success and result.returncode != 0:
        print(result.stdout)
        print(result.stderr, file=sys.stderr)
        raise SystemExit(f'{name} failed after {elapsed:.0f}s')
    if not expect_success and result.returncode == 0:
        print(result.stdout)
        raise SystemExit(f'{name} succeeded and had to refuse')
    print(f'  {name}: {"ok" if result.returncode == 0 else "refused"} in {elapsed:.0f}s',
          flush=True)
    return result


def refusal_says(result: subprocess.CompletedProcess, fragment: str) -> None:
    """A refusal for the wrong reason is not evidence for the right one."""
    blob = result.stdout + result.stderr
    if fragment not in blob:
        raise SystemExit(f'refused, but not for {fragment!r}:\n{blob[-2000:]}')


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--work', default=None)
    parser.add_argument('--keep', action='store_true')
    options = parser.parse_args()

    work = Path(options.work) if options.work else Path(tempfile.mkdtemp(prefix='phase2-cli-'))
    work.mkdir(parents=True, exist_ok=True)
    print(f'working in {work}', flush=True)

    build = subprocess.run(['cargo', 'build', '--release', '--bins'], cwd=CRATE,
                           capture_output=True, text=True)
    if build.returncode:
        raise SystemExit('the binaries do not build:\n' + build.stderr[-3000:])

    beacon_file = work / 'beacon.txt'
    beacon_file.write_bytes(BEACON)
    ceremony = work / 'ceremony'

    print('\nthe ceremony as people would run it', flush=True)
    run([str(BINARIES / 'phase2-begin'), str(ceremony)])
    run([str(BINARIES / 'phase2-contribute'), str(ceremony)])

    # A participant who does not want to rely on the machine's generator
    # alone. Stirred in, never substituted.
    extra = work / 'extra-entropy'
    extra.write_bytes(os.urandom(4096))
    run([str(BINARIES / 'phase2-contribute'), str(ceremony), '--entropy-file', str(extra)])
    extra.unlink()

    run([str(BINARIES / 'phase2-finalise'), str(ceremony), str(beacon_file)])
    verified = run([str(BINARIES / 'phase2-verify'), str(ceremony),
                    '--vk-out', str(work / 'verifying-key.bin')])

    # --- what came out ----------------------------------------------------
    record = json.loads((ceremony / 'ceremony.json').read_text())
    key = (work / 'verifying-key.bin').read_bytes()
    print('\nwhat came out', flush=True)
    print(f'  steps            {[entry["kind"] for entry in record["entries"]]}')
    print(f'  verifying key    {len(key)} bytes, {hashlib.sha256(key).hexdigest()[:32]}')
    print(f'  contributions    {(ceremony / "contributions.bin").stat().st_size} bytes')

    if len(key) != 1248:
        raise SystemExit(f'the verifying key is {len(key)} bytes, not 1248')
    if [entry['kind'] for entry in record['entries']] != ['participant', 'participant', 'beacon']:
        raise SystemExit(f'unexpected steps: {record["entries"]}')
    if 'This ceremony is finished' not in verified.stdout:
        raise SystemExit('a finished ceremony was not reported as finished')

    # The directory carries no secret, which is what makes it publishable.
    for name in ('ceremony.json', 'contributions.bin', 'beacon.bin'):
        if 'secret' in (ceremony / name).read_bytes().lower().decode('latin-1'):
            raise SystemExit(f'{name} mentions a secret')

    # --- the refusals -----------------------------------------------------
    print('\nrefusals that must happen', flush=True)

    refusal_says(
        run([str(BINARIES / 'phase2-contribute'), str(ceremony)], expect_success=False),
        'already been finalised')

    refusal_says(
        run([str(BINARIES / 'phase2-finalise'), str(ceremony), str(beacon_file)],
            expect_success=False),
        'already been finalised')

    refusal_says(
        run([str(BINARIES / 'phase2-begin'), str(ceremony)], expect_success=False),
        'already holds a ceremony')

    # Two contributions exchanged. Every point is still a point in the
    # prime-order subgroup and every contribution is internally valid, so the
    # decoder has nothing to say -- what fails is the chain.
    #
    # An earlier version of this flipped a bit instead, and was refused by blst
    # with BLST_POINT_NOT_ON_CURVE: a real refusal, from the decoder, proving
    # nothing about the audit. A reordering is the version only the audit can
    # catch.
    reordered = work / 'reordered'
    shutil.rmtree(reordered, ignore_errors=True)
    shutil.copytree(ceremony, reordered)
    blob = (reordered / 'contributions.bin').read_bytes()
    first, second, rest = blob[:672], blob[672:1344], blob[1344:]
    (reordered / 'contributions.bin').write_bytes(second + first + rest)
    refusal_says(run([str(BINARIES / 'phase2-verify'), str(reordered)], expect_success=False),
                 'proof of knowledge')

    # A different beacon than the one the ceremony was closed with, **with the
    # record updated to match it**. Without that update the record's own
    # digest check refuses first and the recomputation is never reached --
    # which is how an earlier version of this passed while proving nothing.
    swapped = work / 'swapped-beacon'
    shutil.rmtree(swapped, ignore_errors=True)
    shutil.copytree(ceremony, swapped)
    (swapped / 'beacon.bin').write_bytes(OTHER_BEACON)
    swapped_record = json.loads((swapped / 'ceremony.json').read_text())
    swapped_record['entries'][-1]['beacon_sha256'] = hashlib.sha256(OTHER_BEACON).hexdigest()
    (swapped / 'ceremony.json').write_text(json.dumps(swapped_record, indent=2) + '\n')
    refusal_says(run([str(BINARIES / 'phase2-verify'), str(swapped)], expect_success=False),
                 'not the one this beacon determines')

    # The record and the key travelling separately, which a bad copy produces.
    #
    # The *record's* digest is what changes, not the key: flipping a bit in
    # key.bin corrupts a compressed curve point and is refused by
    # `deserialize_compressed` in a second, which says nothing about whether
    # the two files are checked against each other. An earlier version did
    # exactly that and passed while proving nothing.
    split = work / 'split'
    shutil.rmtree(split, ignore_errors=True)
    shutil.copytree(ceremony, split)
    split_record = json.loads((split / 'ceremony.json').read_text())
    split_record['key_sha256'] = '99' * 32
    (split / 'ceremony.json').write_text(json.dumps(split_record, indent=2) + '\n')
    refusal_says(run([str(BINARIES / 'phase2-verify'), str(split)], expect_success=False),
                 'do not describe the same ceremony')

    # A record listing a step the contributions file does not carry.
    short = work / 'short'
    shutil.rmtree(short, ignore_errors=True)
    shutil.copytree(ceremony, short)
    blob = (short / 'contributions.bin').read_bytes()
    (short / 'contributions.bin').write_bytes(blob[:-672])
    refusal_says(run([str(BINARIES / 'phase2-verify'), str(short)], expect_success=False),
                 'lists')

    # A directory that claims to be freshly opened but whose key is not the
    # starting key.
    #
    # This is the case with no chain to audit: the first participant has
    # nothing to check their key against except the starting key they rebuilt.
    # The record's own two digests cannot supply it -- whoever prepared the
    # directory wrote both -- so a record can carry the true starting digest
    # beside a `key_sha256` for some other key, and a contribution made there
    # would be applied to that other key instead.
    substituted = work / 'substituted-key'
    shutil.rmtree(substituted, ignore_errors=True)
    substituted.mkdir()
    fresh = json.loads((ceremony / 'ceremony.json').read_text())
    fresh['entries'] = []
    # The finished key stands in for "some other key": it is a real, valid
    # proving key over the same circuit, which is the hard case.
    shutil.copy(ceremony / 'key.bin', substituted / 'key.bin')
    fresh['key_sha256'] = hashlib.sha256((ceremony / 'key.bin').read_bytes()).hexdigest()
    fresh['transcript'] = 'ff' * 32
    (substituted / 'ceremony.json').write_text(json.dumps(fresh, indent=2) + '\n')
    (substituted / 'contributions.bin').write_bytes(b'')
    refusal_says(
        run([str(BINARIES / 'phase2-contribute'), str(substituted)], expect_success=False),
        'must be the starting key')

    # A record whose beacon is not the last step.
    #
    # `is_finished` is false for this and for a ceremony that simply has not
    # been closed yet, so the two read alike -- and they are not alike at all.
    # Whoever contributed after the beacon already knew the value the beacon
    # was there to supply, so the final delta depends on nothing unpredictable.
    # The ceremony has to be run again, and nothing that only looked at
    # `is_finished` would say so.
    out_of_place = work / 'beacon-not-last'
    shutil.rmtree(out_of_place, ignore_errors=True)
    shutil.copytree(ceremony, out_of_place)
    shuffled = json.loads((out_of_place / 'ceremony.json').read_text())
    entries = shuffled['entries']
    entries[1], entries[2] = entries[2], entries[1]
    for position, entry in enumerate(entries):
        entry['index'] = position + 1
    (out_of_place / 'ceremony.json').write_text(json.dumps(shuffled, indent=2) + '\n')
    refusal_says(run([str(BINARIES / 'phase2-verify'), str(out_of_place)], expect_success=False),
                 'not the last one')
    refusal_says(
        run([str(BINARIES / 'phase2-contribute'), str(out_of_place)], expect_success=False),
        'not the last one')

    print('\nthe ceremony ran and every refusal fired')
    if not options.keep and options.work is None:
        shutil.rmtree(work, ignore_errors=True)
    else:
        print(f'kept in {work}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
