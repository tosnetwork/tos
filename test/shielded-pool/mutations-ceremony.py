#!/usr/bin/env python3
"""Weaken the phase-2 ceremony one check at a time and require the suite to
report it, by name.

The first stage of phase 2 could be checked by equality against `ark-groth16`.
The contribution step cannot: there is nothing to agree with, so the evidence
that its verifier works is that it refuses every forgery that does not need a
discrete log broken -- and the evidence that the *tests* work is this file.

Two rules, both learned the hard way on this code:

* a mutation that turns the wrong test red is not evidence for the one it was
  aimed at. Several checks here shadow each other -- the transcript binding
  catches a reordered chain before the chain link is consulted, the query check
  catches a mangled `delta_g2` before the cross-group check is -- so every case
  names the test that must fail, and a suite that goes red elsewhere counts as
  a survivor;
* a mutation that fails to compile is not evidence at all. An early run of this
  battery reported every mutation killed because the tree did not build before
  any of them was applied.

`pok-challenge-points` removes the participant's own `s` and `s_delta` from
the challenge hash. A public rerandomization now distinguishes that build:
scale both points by the same public factor, leaving the key and all other
contribution fields unchanged. The weakened verifier accepts the modified
proof. This tests proof binding, not scalar recovery or a forged pool proof.

The anchors below are exact source text, so `rustfmt` can invalidate them
without changing a line of logic -- it collapsed two multi-line calls the first
time this ran after formatting. That aborts with `anchor appears 0 times`,
which means the anchor needs re-copying from the source, not that anything is
broken.

Usage: mutations-ceremony.py [--only NAME ...]
"""
from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CRATE = ROOT / 'tools/shielded-pool-ceremony'
CONTRIBUTION = CRATE / 'src/contribution.rs'
SECRET = CRATE / 'src/secret.rs'
ENTROPY = CRATE / 'src/entropy.rs'
RECORD = CRATE / 'src/record.rs'
CROSSCHECK = CRATE / 'src/crosscheck.rs'

# Marker for any explicitly recorded coverage gap.
UNTESTED = '<no test: rests on the security proof, not on this suite>'


@dataclass
class Case:
    name: str
    why: str
    path: Path
    before: str
    after: str
    expect: str


CASES = [
    # What a contribution does to the key. Both of these leave a key that
    # parses, has the right shape, and proves nothing.
    Case('h-not-divided', 'the H query is left undivided', CONTRIBUTION,
         '    key.h_query = divide(&key.h_query);\n', '',
         'a_key_still_proves_after_one_contribution'),
    Case('l-not-divided', 'the L query is left undivided', CONTRIBUTION,
         '    key.l_query = divide(&key.l_query);\n', '',
         'a_key_still_proves_after_one_contribution'),

    # The challenge, which is what binds a proof to one position of one
    # ceremony.
    Case('pok-challenge-transcript', 'the challenge ignores the transcript', CONTRIBUTION,
         '    message.extend_from_slice(&transcript.digest);\n', '',
         'a_step_checked_against_the_wrong_transcript_is_rejected'),
    Case('pok-challenge-points', "the challenge ignores the participant's own points",
         CONTRIBUTION,
         '    message.extend_from_slice(&g1_to_uncompressed(s));\n'
         '    message.extend_from_slice(&g1_to_uncompressed(s_delta));\n', '',
         'publicly_rerandomizing_the_proof_points_is_rejected'),

    # The transcript itself.
    Case('transcript-absorb', 'the transcript does not absorb the contribution', CONTRIBUTION,
         '        hasher.update(contribution.to_bytes());\n', '',
         'the_transcript_is_determined_by_what_is_published'),
    Case('transcript-chain', 'the transcript does not carry its own history', CONTRIBUTION,
         '        hasher.update(self.digest);\n', '',
         'the_transcript_is_determined_by_what_is_published'),

    # verify_step's checks, one at a time.
    Case('step-queries', 'the step does not check how the queries were divided', CONTRIBUTION,
         '    queries_were_divided_by_the_same_scalar(before, after, entropy)?;\n'
         '    the_rest_is_untouched(before, after)',
         '    let _ = entropy;\n    the_rest_is_untouched(before, after)',
         'queries_divided_by_a_different_scalar_are_caught'),
    Case('step-untouched', 'the step does not check the sections a contribution may not move',
         CONTRIBUTION,
         '    queries_were_divided_by_the_same_scalar(before, after, entropy)?;\n'
         '    the_rest_is_untouched(before, after)',
         '    queries_were_divided_by_the_same_scalar(before, after, entropy)?;\n    Ok(())',
         'touching_anything_but_delta_is_caught'),
    Case('step-cross-group', 'the step does not compare delta across the groups', CONTRIBUTION,
         '    if !delta_agrees_across_groups(after.delta_g1, after.vk.delta_g2) {',
         '    if false {',
         'a_delta_that_differs_between_the_groups_is_caught'),
    Case('step-delta-moved', 'the step accepts a delta that did not move', CONTRIBUTION,
         '    if before.delta_g1 == after.delta_g1 {', '    if false {',
         'a_genuine_contribution_of_one_is_refused'),
    Case('step-chain-link', 'the step does not tie the proof to the delta it moved',
         CONTRIBUTION,
         '    if !same_pairing(after.delta_g1, challenge, before.delta_g1, '
         'contribution.r_delta) {',
         '    if false {',
         'a_delta_that_does_not_follow_from_the_proof_is_caught'),
    Case('pok-pairing', 'the proof of knowledge is not checked', CONTRIBUTION,
         '    if !same_pairing(contribution.s, contribution.r_delta, contribution.s_delta, '
         'challenge) {', '    if false {',
         'a_proof_that_disagrees_between_the_groups_is_caught'),

    # The batched check is only a check if its weights are unpredictable to
    # whoever built the key.
    Case('batch-weights', 'the batching weights come from a constant', CONTRIBUTION,
         '    let mut seed = [0u8; 32];\n    entropy.fill(&mut seed)?;',
         '    let mut seed = [0u8; 32];\n    let _ = entropy;\n    seed[0] = 1;',
         'verification_draws_its_weights_from_the_caller'),

    Case('batch-weights-are-one', 'the batching weights are all one', CONTRIBUTION,
         '    Ok((0..count).map(|_| Fr::rand(&mut rng)).collect())',
         '    let _ = &mut rng;\n    Ok((0..count).map(|_| Fr::from(1u64)).collect())',
         'the_weights_are_what_catches_a_compensating_pair'),

    # verify_chain's checks. Separate code from verify_step's, so separate
    # cases -- an auditor years from now runs this one and not the other.
    Case('chain-final-delta', "the audit does not tie the final key to the chain's end",
         CONTRIBUTION,
         '    if final_key.delta_g1 != last.delta_g1 || final_key.vk.delta_g2 != last.delta_g2 {',
         '    if false {', 'a_final_key_that_is_not_the_chains_is_caught'),
    Case('chain-advance', 'the audit does not advance to the next delta', CONTRIBUTION,
         '        previous_g1 = contribution.delta_g1;\n', '',
         'a_whole_chain_verifies_without_the_intermediate_keys'),
    Case('chain-transcript', 'the audit does not advance the transcript', CONTRIBUTION,
         '        transcript = transcript.extend(contribution);\n', '',
         'a_whole_chain_verifies_without_the_intermediate_keys'),
    Case('chain-anchor', 'the audit accepts an anchor that is not the start', CONTRIBUTION,
         '    if initial.delta_g1 != G1Affine::generator() || initial.vk.delta_g2 != '
         'G2Affine::generator() {', '    if false {',
         'an_audit_anchored_after_the_start_is_refused'),
    Case('chain-cross-group', 'the audit does not compare delta across the groups',
         CONTRIBUTION,
         '        if !delta_agrees_across_groups(contribution.delta_g1, contribution.delta_g2) {',
         '        if false {', 'a_delta_that_differs_between_the_groups_is_caught'),
    Case('chain-link', 'the audit does not link one delta to the previous', CONTRIBUTION,
         '        if !same_pairing(contribution.delta_g1, challenge, previous_g1, '
         'contribution.r_delta) {',
         '        if false {', 'a_delta_that_does_not_follow_from_the_proof_is_caught'),

    # The ending. A beacon's scalar is public, so the only property it has is
    # that it was determined by bytes nobody could predict -- and the only
    # thing protecting that property is that it is recomputed rather than
    # trusted.
    Case('beacon-ignored', 'the finalising scalar does not depend on the beacon', CONTRIBUTION,
         '    hasher.update(beacon);\n', '',
         'a_different_beacon_gives_a_different_ending'),
    Case('beacon-not-recomputed', 'the finalising step is trusted instead of recomputed',
         CONTRIBUTION,
         '    if expected.to_bytes() != contribution.to_bytes() {', '    if false {',
         'a_chosen_scalar_wearing_the_beacons_name_is_caught'),
    Case('beacon-length', 'a beacon short enough to grind out in advance is accepted',
         CONTRIBUTION,
         '    if beacon.len() < MINIMUM_BEACON_BYTES {', '    if false {',
         'a_beacon_too_short_to_be_unpredictable_is_refused'),

    # The published bytes, which two implementations have to agree on.
    Case('bytes-delta-g2', "the published bytes omit delta's G2 half", CONTRIBUTION,
         '        out[96..288].copy_from_slice(&g2_to_uncompressed(&self.delta_g2));\n', '',
         'a_contribution_round_trips'),

    # The secret. None of these is detectable from the outside of a ceremony,
    # which is exactly why they are checked from the inside.
    Case('secret-zero', 'a secret of zero is accepted', SECRET,
         '        if value.is_zero() {', '        if false {',
         'secret::tests::a_zero_draw_is_refused'),
    Case('secret-one', 'a secret of one is accepted', SECRET,
         '        if value == Fr::ONE {', '        if false {',
         'secret::tests::a_draw_of_one_is_refused'),
    Case('secret-narrow', 'the secret is reduced from 32 bytes instead of 64', SECRET,
         '        let value = Fr::from_le_bytes_mod_order(wide.as_ref());',
         '        let value = Fr::from_le_bytes_mod_order(&wide.as_ref()[..32]);',
         'secret::tests::the_whole_draw_is_used'),
    Case('secret-printed', 'the secret prints itself', SECRET,
         '        formatter.write_str("Secret(<withheld>)")',
         '        write!(formatter, "Secret({})", self.value.into_bigint())',
         'secret::tests::the_value_is_not_in_the_debug_output'),

    # The second implementation. A cross-check that cannot fail is not a
    # cross-check: if the blst side agreed with arkworks by construction --
    # by never objecting, or by comparing the wrong things -- the agreement
    # tests would be green against a library that was not being asked.
    Case('blst-pairing-order', 'the second pairing takes its arguments the other way round',
         CROSSCHECK,
         '        blst::blst_miller_loop(&mut right, &d, &c);',
         '        blst::blst_miller_loop(&mut right, &b, &c);',
         'both_accept_an_honest_chain'),
    Case('blst-pairing-trivial', 'the blst pairing always agrees', CROSSCHECK,
         '        Ok(blst::blst_fp12_finalverify(&left, &right))',
         '        let _ = blst::blst_fp12_finalverify(&left, &right);\n        Ok(true)',
         'both_refuse_every_forgery'),
    # Not `both_accept_an_honest_chain`: an unweighted sum accepts an honest
    # chain perfectly well, and catches every forgery that scales one point.
    # A compensating pair is the only thing that tells the two apart, which is
    # exactly why that test had to be written before this case could pass.
    Case('blst-scalar-dropped', 'the batching weights are not applied', CROSSCHECK,
         '            blst::blst_p1_mult(&mut term, &base, blst_scalar.b.as_ptr(), 255);',
         '            term = base;',
         'the_weights_are_what_catches_a_compensating_pair'),
    Case('blst-skips-the-proof', 'the blst side does not check the proof of knowledge',
         CROSSCHECK,
         '        if !same_pairing(&contribution.s, &contribution.r_delta, &contribution.s_delta, '
         '&challenge)?\n        {',
         '        if false\n        {',
         'both_refuse_a_forgery_aimed_at_each_check'),
    Case('blst-skips-the-queries', 'the blst side does not check the query division',
         CROSSCHECK,
         '        if !same_pairing(&after_sum, &final_key.vk.delta_g2, &before_sum, '
         '&initial.vk.delta_g2)? {',
         '        if false {',
         'both_refuse_every_forgery'),
    Case('blst-skips-the-chain-link', 'the blst side does not link one delta to the previous',
         CROSSCHECK,
         '        if !same_pairing(&contribution.delta_g1, &challenge, &previous_g1, '
         '&contribution.r_delta)? {',
         '        if false {',
         'both_refuse_a_forgery_aimed_at_each_check'),
    Case('blst-skips-the-cross-group', 'the blst side does not compare delta across the groups',
         CROSSCHECK,
         '        if !same_pairing(\n            &contribution.delta_g1,\n            &generator_g2,\n'
         '            &generator_g1,\n            &contribution.delta_g2,\n        )? {',
         '        if false {',
         'both_refuse_a_forgery_aimed_at_each_check'),

    # What a ceremony leaves on disk. None of this is cryptography and all of
    # it is what an auditor is handed, so a directory that lies quietly is as
    # bad as a pairing that passes wrongly.
    Case('record-overwrite', 'a ceremony may be begun over an existing one', RECORD,
         '        if self.exists() {', '        if false {',
         'record::tests::beginning_over_an_existing_ceremony_is_refused'),
    Case('record-key-digest', 'the key is not held to the digest the record states', RECORD,
         '        if actual != recorded {', '        if false {',
         'record::tests::a_key_that_does_not_match_its_record_is_refused'),
    Case('record-ragged', 'a contributions file of any length is accepted', RECORD,
         '        if bytes.len() % CONTRIBUTION_BYTES != 0 {', '        if false {',
         'record::tests::a_contributions_file_of_the_wrong_length_is_refused'),
    Case('record-protocol', "another protocol's record is read as this one", RECORD,
         '        if record.protocol != PROTOCOL {', '        if false {',
         'record::tests::a_record_for_another_protocol_is_refused'),

    Case('record-beacon-last', 'a beacon with contributions after it goes unnoticed', RECORD,
         '                *position != last && matches!(entry.step, Step::Beacon { .. })',
         '                false && *position != last && matches!(entry.step, Step::Beacon { .. })',
         'record::tests::a_beacon_that_is_not_last_is_spotted'),

    # The entropy source.
    Case('entropy-constant', 'a source returning one repeated byte is used', ENTROPY,
         '        Some(first) if bytes.len() > 1 && bytes.iter().all(|byte| byte == first) => {',
         '        Some(first) if false && bytes.iter().all(|byte| byte == first) => {',
         'entropy::tests::a_constant_block_is_refused'),
    Case('stir-material', "stirring ignores the participant's material", ENTROPY,
         '            hasher.update(&self.material);\n', '',
         'entropy::tests::the_material_changes_the_answer'),
    Case('stir-inner', 'stirring ignores the system generator', ENTROPY,
         '            hasher.update(fresh.as_ref());\n', '',
         'entropy::tests::the_inner_source_is_not_ignored'),
    Case('stir-one-block', 'a long draw expands one read instead of taking several', ENTROPY,
         '            self.inner.fill(fresh.as_mut())?;\n            self.counter = self.counter',
         '            if self.counter == 0 { self.inner.fill(fresh.as_mut())?; }\n'
         '            self.counter = self.counter',
         'entropy::tests::each_block_reads_the_inner_source_again'),
    Case('stir-empty', 'stirring in nothing is offered as protection', ENTROPY,
         '        if material.is_empty() {', '        if false {',
         'entropy::tests::stirring_in_nothing_is_refused'),
]


def run_suite() -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env['PATH'] = str(Path.home() / '.cargo/bin') + os.pathsep + env.get('PATH', '')
    env['CARGO_TERM_COLOR'] = 'never'
    # Three targets in one invocation: the entropy, secret and record checks
    # are unit tests inside the library, the forgeries are one integration
    # suite and the two-library agreement is another, and a mutation has to be
    # shown against whichever one owns it.
    #
    # `crosscheck_agrees` was left out of this list when it was added, and
    # every mutation of the blst implementation survived -- correctly, since
    # nothing was running it. A second implementation nothing exercises is
    # worse than none, because it reads like evidence.
    #
    # `--no-fail-fast` is load-bearing for the same reason. `cargo test` stops
    # at the first failing target, so with two suites a mutation that turns
    # both red would only ever report the first, and every case naming a test
    # in the other one came back WRONG-TEST -- a report of the instrument
    # stopping, not of the mutation surviving.
    return subprocess.run(
        ['cargo', 'test', '--no-fail-fast', '--lib', '--test', 'phase2_contribution',
         '--test', 'crosscheck_agrees', '--', '--test-threads=4'],
        cwd=CRATE, capture_output=True, text=True, timeout=3600, env=env)


def failed_tests(output: str) -> set[str]:
    return set(re.findall(r'^test (\S+) \.\.\. FAILED$', output, flags=re.M))


def build_parser() -> argparse.ArgumentParser:
    """The options this battery accepts, separated so a test can ask.

    `ceremony-docs-tests.py` reads the flags straight off this parser rather
    than off `--help` output, because help text is prose and prose can name a
    flag the parser no longer has.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument('--only', nargs='*', default=None)
    parser.add_argument(
        '--check-anchors',
        action='store_true',
        help='check that every anchor still matches the source, then stop. '
             'Under a second, and it is the whole of what CI can afford to run.',
    )
    return parser


def main() -> int:
    options = build_parser().parse_args()
    cases = CASES if options.only is None else [c for c in CASES if c.name in options.only]
    if options.only and len(cases) != len(options.only):
        raise SystemExit(f'unknown case name in {options.only}')

    # Every anchor, checked by counting, before a single suite is run.
    #
    # A mismatch used to surface as `anchor appears 0 times` partway through a
    # thirty-five minute run, after everything before it had already been
    # spent. Counting answers the same question in well under a second, and
    # the question is asked often: any edit to the files below can move one.
    sources = {case.path: case.path.read_text() for case in CASES}
    stale = [
        (case.name, case.path.name, count)
        for case in CASES
        if (count := sources[case.path].count(case.before)) != 1
    ]
    if stale:
        lines = "\n".join(
            f"  {name}: appears {count} times in {filename}, expected once"
            for name, filename, count in stale
        )
        raise SystemExit(
            "anchors no longer match the source -- re-copy them before running:\n" + lines
        )
    print(f"{len(CASES)} anchors, each appearing once", flush=True)
    if options.check_anchors:
        return 0

    baseline = run_suite()
    blob = baseline.stdout + baseline.stderr
    if 'error[' in blob or 'could not compile' in blob:
        raise SystemExit('the crate does not build before any mutation:\n' + blob[-4000:])
    if baseline.returncode:
        raise SystemExit('the suite is not green before any mutation:\n' + blob[-4000:])
    print('baseline green', flush=True)

    problems = []
    for case in cases:
        original = case.path.read_text()
        count = original.count(case.before)
        if count != 1:
            raise SystemExit(f'{case.name}: anchor appears {count} times, expected once')
        try:
            case.path.write_text(original.replace(case.before, case.after))
            result = run_suite()
            output = result.stdout + result.stderr
            failures = failed_tests(output)
            if 'error[' in output or 'could not compile' in output:
                problems.append(f'{case.name}: no longer compiles, which is not evidence')
                verdict = 'UNCOMPILED'
            elif case.expect is UNTESTED:
                if failures:
                    problems.append(
                        f'{case.name}: recorded as not test-backed, but {sorted(failures)} '
                        'now catches it -- update this file')
                    verdict = 'NEWLY-CAUGHT'
                else:
                    verdict = 'survives (recorded)'
            elif result.returncode == 0:
                problems.append(f'{case.name}: the suite stayed green')
                verdict = 'SURVIVED'
            elif case.expect not in failures:
                problems.append(f'{case.name}: failed as {sorted(failures)}, not {case.expect}')
                verdict = 'WRONG-TEST'
            else:
                verdict = 'killed'
            print(f'{case.name:26} {case.why:62} {verdict}', flush=True)
        finally:
            case.path.write_text(original)

    restored = run_suite()
    if restored.returncode:
        raise SystemExit('the suite did not come back green:\n'
                         + restored.stdout + restored.stderr)
    print('green again', flush=True)

    if problems:
        print('\nPROBLEMS:', file=sys.stderr)
        for line in problems:
            print('  ' + line, file=sys.stderr)
        return 1
    recorded = sum(1 for case in cases if case.expect is UNTESTED)
    print(f'\n{len(cases)} mutations, {len(cases) - recorded} killed by the test they were '
          f'aimed at, {recorded} recorded as not test-backed')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
