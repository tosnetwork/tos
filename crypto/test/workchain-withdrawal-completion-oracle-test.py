#!/usr/bin/env python3
"""Synthetic observer tests ONLY. No simulated observation is a host contract pass."""
from copy import deepcopy
import unittest
from workchain_withdrawal_completion_oracle import check, expect_red, check_abort, Violation


def fixture(case):
    i = dict(x=100, y=90, slot=7, base=2, units=3, Q=10, window=5, height=16,
             phase=1, withdrawal_id='ab'*32, account_id='cd'*32, src='ef'*32,
             system_count=0, system_limit=2, account_closed=False, native_bucket_cost=0)
    b = dict(R_actual=1000, R_book=1000, N_book=1000, P=100, W=100, D=0,
             coordinator=500, holdings=100, refundable=20, issuance_fees=0, sequence=8,
             pending=[], system_count=0, system_pending_root='unchanged-system', user_pending_root='unchanged', records={i['withdrawal_id']:100})
    if case in ('row5', 'sweep-atomic', 'bucket-closed'):
        b.update(P=0, W=0, records={})
    a = deepcopy(b)
    o = dict(before=b, after=a, published=True, closure_events=[], value_movements=[])
    if case in ('row6', 'row5'):
        o['dispatch'] = ['late-return-admission']
        a.update(R_actual=1077, R_book=1077, N_book=1077, P=0, W=0, records={},
                 coordinator=507, issuance_fees=6, sequence=9,
                 pending=[dict(target=i['account_id'], amount=77)], system_count=1)
    elif case == 'row4':
        o.update(dispatch=['lazy-owner-settlement'], closure_events=[i['withdrawal_id']])
        a.update(P=0, W=0, records={})
        for name in ('y', 'slot', 'base', 'units'):
            del i[name]
    elif case.startswith('bucket-'):
        if case == 'bucket-small':
            i['y'] = 13
        if case == 'bucket-full':
            i['system_count'] = i['system_limit'] = 2
            b['pending'] = [dict(target=i['account_id'], amount=2)] * 2
            b['system_count'] = 2; a['pending'] = deepcopy(b['pending']); a['system_count'] = 2
        if case == 'bucket-closed':
            i['account_closed'] = True
        o.update(dispatch=['type2-bucket-disposition'], bucket_native_credit=i['y'],
                 bucket_entries_added=[dict(kind=2, src=i['src'], account_id=i['account_id'],
                                          tomis=i['y'], return_failed=False)])
        a.update(P=0, W=0, records={}, coordinator=500+i['y'], holdings=100+i['y'])
    else:
        o.update(custody_transfer=77, operator_slot_income=7,
                 component_batch_ids=['batch1']*4, committed_batch_id='batch1')
        a.update(R_actual=1077, R_book=1077, N_book=1077, holdings=10, coordinator=417,
                 issuance_fees=6, sequence=9, pending=[dict(target=i['account_id'], amount=77)], system_count=1)
    return dict(input=i, observed=o)


class Observer(unittest.TestCase):
    def test_positive_observer_cases_only(self):
        for case in ('row6','row5','row4','bucket-small','bucket-full','bucket-closed','sweep-atomic'):
            with self.subTest(case=case):
                check(case, fixture(case))

    def test_row6_exact_row3_misroute_all_amounts_unchanged(self):
        value = fixture('row6'); old = deepcopy(value['observed']['after'])
        value['observed']['dispatch'] = ['within-window-failed']
        self.assertEqual(value['observed']['after'], old)
        expect_red('row6', value, 'LATE_NOT_ROW3')
        print('ROW6 misroute red at LATE_NOT_ROW3; R/N/P/W and receipt unchanged')
        with self.assertRaisesRegex(Violation, '^ORACLE_MISSING:LATE_NOT_ROW3$'):
            expect_red('row6', value, 'LATE_NOT_ROW3', observer=lambda *args: None)

    def test_wrong_earlier_failure_does_not_count(self):
        value = fixture('row6'); value['observed']['published'] = False
        with self.assertRaisesRegex(Violation, '^WRONG_FAILURE_LAYER:DISPOSITION_MUST_PUBLISH$'):
            expect_red('row6', value, 'LATE_NOT_ROW3')

    def test_row5_cannot_release_again(self):
        value = fixture('row5'); value['observed']['after']['P'] = 1
        expect_red('row5', value, 'DELTA_P')

    def test_row4_never_triggered_and_hidden_value_move(self):
        value = fixture('row4'); value['observed']['after'] = deepcopy(value['observed']['before'])
        expect_red('row4', value, 'RECORD_CLOSURE')
        value = fixture('row4'); value['observed']['value_movements'] = [('out',1),('in',1)]
        expect_red('row4', value, 'ROW4_NO_VALUE_MOVEMENT')
        for field in ('R_actual','N_book','coordinator','issuance_fees','sequence'):
            value = fixture('row4'); value['observed']['after'][field] += 1
            expect_red('row4', value, 'DELTA_'+field)

    def test_refusal_without_bucket_is_not_success(self):
        for case in ('bucket-small','bucket-full','bucket-closed'):
            value=fixture(case); value['observed']['published']=False
            expect_red(case,value,'DISPOSITION_MUST_PUBLISH')
            value=fixture(case); value['observed']['dispatch']=['helper-refused']
            expect_red(case,value,'REFUSAL_IS_NOT_DISPOSITION')
            value=fixture(case); value['observed']['bucket_entries_added']=[]
            expect_red(case,value,'BUCKET_FIXED_ATTRIBUTION')

    def test_attribution_and_no_receipt(self):
        value=fixture('bucket-small'); value['observed']['bucket_entries_added'][0]['body']='variable'
        expect_red('bucket-small',value,'BUCKET_FIXED_ATTRIBUTION')
        value=fixture('bucket-small'); value['observed']['after']['sequence']+=1
        expect_red('bucket-small',value,'DELTA_sequence')

    def test_d63_each_missing_component_and_mixed_batch(self):
        for name, mutate in (
            ('D63_1_PHYSICAL_TRANSFER',lambda o:o.update(custody_transfer=0)),
            ('D63_2_HOLDINGS',lambda o:o['after'].update(holdings=100)),
            ('D63_3_FEE_DESTINATIONS',lambda o:o['after'].update(issuance_fees=0)),
            ('D63_4_INSTALLED_CREDIT',lambda o:o['after'].update(N_book=1000)),
            ('D63_SAME_BATCH',lambda o:o.update(component_batch_ids=['batch1']*3+['batch2']))):
            value=fixture('sweep-atomic'); mutate(value['observed'])
            expect_red('sweep-atomic',value,name)
            print('SYNTHETIC_ORACLE_RED '+name)

    def test_d63_abort_with_early_publication(self):
        value=dict(before={'root':'a'},after={'root':'a'},published_movements=[])
        check_abort(value); value['published_movements']=[('custody',77)]
        with self.assertRaisesRegex(Violation,'^D63_ABORT_ZERO_PUBLICATION$'):
            check_abort(value)

    def test_checked_not_wrapped(self):
        value=fixture('row6'); value['input']['base']=2**64-1
        expect_red('row6',value,'CHECKED_INPUT')


if __name__=='__main__':
    unittest.main()
