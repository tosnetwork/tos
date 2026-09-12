"""Independent table oracle. JSON observations require a reviewed real-host adapter.

Selftests exercise this observer only, never certify an authenticated host path.
No expected value or routing decision is read from proposed effects.
"""
MAX = (1 << 64) - 1
FIELDS = ('R_actual', 'R_book', 'N_book', 'P', 'W', 'D', 'coordinator',
          'holdings', 'refundable', 'issuance_fees', 'sequence')


class Violation(Exception):
    pass


def require(condition, name):
    if not condition:
        raise Violation(name)


def checked(value):
    require(type(value) is int and 0 <= value <= MAX, 'CHECKED_INPUT')
    return value


def check_phase_transition(data):
    """D73's existing remaining-work slot; actual queue and committed W cuts.

    Queue membership comes from the adapter's Native queue enumeration, not
    payout_absent(), its logs, or a proposed effects record. This does not turn
    an orphan fixture into an authenticated predecessor.
    """
    i, o = data['input'], data['observed']
    require(o['published'] is True, 'PHASE_PUBLICATION')
    steps = o['steps']
    require([step['name'] for step in steps] == ['prepare', 'owner5', 'owner6'],
            'PHASE_EXECUTION_PATH')
    identity = i['withdrawal_id']
    message = dict(source=i['custody'], created_lt=checked(i['created_lt']),
                   hash=i['payout_hash'])
    def record(state):
        matches = [r for r in state['withdrawals'] if r['id'] == identity]
        require(len(matches) <= 1, 'PHASE_IDENTITY_UNIQUE')
        return matches[0] if matches else None
    previous = None
    for step in steps:
        before, after = step['before'], step['after']
        require(step['validation'] == 'accept', 'PHASE_VALIDATOR_EXECUTION')
        require(checked(after['height']) == checked(before['height'] + 1), 'PHASE_BLOCK_HEIGHT')
        require(step['old_root'] == before['root'] and step['new_root'] == after['root'],
                'PHASE_QUEUE_BINDING')
        if previous is not None:
            require(before['root'] == previous['root'], 'PHASE_ROOT_CONTINUITY')
        old, new = record(before), record(after)
        require(new is not None, 'PHASE_RECORD_PRESENT')
        for field in ('principal', 'opened', 'window', 'created_lt', 'phase', 'Q'):
            checked(new[field])
        require(new['created_lt'] == message['created_lt'], 'PHASE_QUEUE_BINDING')
        if step['name'] == 'prepare':
            require(old is None and new['phase'] == 0 and new['Q'] == 0 and
                    new['opened'] == after['height'], 'PHASE_PREPARE_RECORD')
            require(after['queue'].count(message) == 1, 'PHASE_PAIRED_ENQUEUE')
        else:
            require(old is not None, 'PHASE_AUTHENTICATED_PREDECESSOR')
            require(all(new[k] == old[k] for k in ('principal', 'opened', 'window', 'created_lt')),
                    'PHASE_RECORD_BINDING')
            require(new['phase'] in (0, 1), 'PHASE_ENCODING')
            if new['phase'] == 1:
                require(new['Q'] > new['opened'], 'PHASE_STRICT_HEIGHT')
                require(checked(new['Q'] + new['window']) <= (1 << 32) - 1, 'PHASE_DEADLINE')
            if old['phase'] == 1:
                require(new['phase'] == 1 and new['Q'] == old['Q'], 'PHASE_Q_IMMUTABLE')
            else:
                absent_later = before['height'] > old['opened'] and message not in before['queue']
                require(new['phase'] == int(absent_later), 'PHASE_QUEUE_BINDING')
                require(new['Q'] == (before['height'] if absent_later else 0), 'PHASE_QUEUE_BINDING')
        previous = after
    require(record(previous)['phase'] == 1, 'PHASE_TRUE_LATER_OBSERVED')


def check(case, data):
    if case == 'phase-transition':
        return check_phase_transition(data)
    i, o = data['input'], data['observed']
    require(o['published'] is True, 'DISPOSITION_MUST_PUBLISH')
    before, after = o['before'], o['after']
    x = checked(i['x'])
    if case != 'row4':
        y, s = (checked(i[k]) for k in ('y', 'slot'))
        g = checked(checked(i['base']) * checked(i['units']))
        h = checked(s + g)
    for state in (before, after):
        for field in FIELDS:
            checked(state[field])
        require(state['system_count'] == len(state['pending']), 'ENUMERATED_SYSTEM_COUNT')
    expected = dict.fromkeys(FIELDS, 0)
    records = dict(before['records'])
    entry = i['withdrawal_id']
    if case in ('row6', 'row5', 'row4'):
        end = checked(checked(i['Q']) + checked(i['window']))
        require(i['phase'] == 1 and checked(i['height']) > end, 'EXPIRED_FIXTURE')
        if case == 'row5':
            require(entry not in records, 'ROW5_ALREADY_CLOSED')
        else:
            require(entry in records and records[entry] == x, 'OPEN_RECORD_FIXTURE')
            del records[entry]
            expected['P'] = expected['W'] = -x
        if case == 'row4':
            require(o['dispatch'] == ['lazy-owner-settlement'], 'ROW4_LAZY_DISPATCH')
            require(o['closure_events'] == [entry], 'ROW4_TRIGGERED')
            require(o['value_movements'] == [], 'ROW4_NO_VALUE_MOVEMENT')
            require(after['pending'] == before['pending'] and
                    after['system_pending_root'] == before['system_pending_root'], 'ROW4_NO_PENDING')
        else:
            # Rows 3 and 6 have IDENTICAL amounts and P/W deltas under D78.
            # This must come from actual dispatcher/callee instrumentation.
            require(o['dispatch'] == ['late-return-admission'], 'LATE_NOT_ROW3')
            amount = checked(y - h)
            require(amount > 0, 'POSITIVE_CREDIT_FIXTURE')
            for field in ('R_actual', 'R_book', 'N_book'):
                expected[field] = amount
            expected['coordinator'], expected['issuance_fees'] = s, g
            expected['sequence'] = 1
            require(after['pending'] == before['pending'] + [
                {'target': i['account_id'], 'amount': amount}], 'LATE_RECEIPT')
    elif case in ('bucket-small', 'bucket-full', 'bucket-closed'):
        if case == 'bucket-small':
            require(y <= h, 'SMALL_VALUE_FIXTURE')
        elif case == 'bucket-full':
            require(i['system_count'] == i['system_limit'], 'FULL_SLOT_FIXTURE')
        else:
            require(i['account_closed'] is True, 'CLOSED_ACCOUNT_FIXTURE')
        require(o['dispatch'] == ['type2-bucket-disposition'], 'REFUSAL_IS_NOT_DISPOSITION')
        # No default for Native routing costs; adapter reads the actual move.
        net = checked(y - checked(i['native_bucket_cost']))
        require(o['bucket_entries_added'] == [dict(kind=2, src=i['src'],
                    account_id=i['account_id'], tomis=net, return_failed=False)], 'BUCKET_FIXED_ATTRIBUTION')
        require(o['bucket_native_credit'] == net, 'BUCKET_PHYSICAL_LOCATION')
        require(after['pending'] == before['pending'] and
                after['system_pending_root'] == before['system_pending_root'], 'BUCKET_NO_RECEIPT')
        expected['coordinator'] = expected['holdings'] = net
        if entry in records:
            del records[entry]
            expected['P'] = expected['W'] = -x
    elif case == 'sweep-atomic':
        amount = checked(y - h)
        require(amount > 0, 'SWEEP_POSITIVE_FIXTURE')
        # Four independent requirements; none is inferred from conservation.
        require(o['custody_transfer'] == amount, 'D63_1_PHYSICAL_TRANSFER')
        require(after['holdings'] - before['holdings'] == -y, 'D63_2_HOLDINGS')
        require(o['operator_slot_income'] == s and
                after['issuance_fees'] - before['issuance_fees'] == g, 'D63_3_FEE_DESTINATIONS')
        require(after['N_book'] - before['N_book'] == amount and
                after['pending'] == before['pending'] + [dict(target=i['account_id'], amount=amount)],
                'D63_4_INSTALLED_CREDIT')
        for field in ('R_actual', 'R_book', 'N_book'):
            expected[field] = amount
        expected.update(holdings=-y, coordinator=-(y-s), issuance_fees=g, sequence=1)
        require(o['component_batch_ids'] == [o['committed_batch_id']] * 4, 'D63_SAME_BATCH')
    else:
        raise Violation('UNKNOWN_CASE')
    require(after['records'] == records, 'RECORD_CLOSURE')
    require(after['user_pending_root'] == before['user_pending_root'], 'USER_PENDING_PRESERVED')
    require(after['system_count'] == len(after['pending']), 'ENUMERATED_SYSTEM_COUNT')
    # For row4 the adapter removes independently observed triggering-operation
    # effects, never the proposed settlement effects. See contract for the cut.
    for field in FIELDS:
        require(after[field] - before[field] == expected[field], 'DELTA_' + field)
    for state in (before, after):
        require(state['R_actual'] == state['R_book'], 'RESERVE_EQUALITY')
        require(state['R_actual'] + state['P'] == state['D'] + state['N_book'] + state['W'], 'RIGHTS_EQUALITY')


def expect_red(case, data, assertion, observer=check):
    try:
        observer(case, data)
    except Violation as error:
        require(str(error) == assertion, 'WRONG_FAILURE_LAYER:' + str(error))
        return
    raise Violation('ORACLE_MISSING:' + assertion)


def check_abort(observation):
    require(observation['before'] == observation['after'] and
            observation['published_movements'] == [], 'D63_ABORT_ZERO_PUBLICATION')


if __name__ == '__main__':
    import argparse
    import json
    import sys
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--case', required=True)
    parser.add_argument('--observation', required=True)
    args = parser.parse_args()
    try:
        with open(args.observation) as stream:
            observation = json.load(stream)
        check(args.case, observation)
    except (OSError, ValueError, KeyError, TypeError, Violation) as error:
        print('COMPLETION_OBSERVER_REJECT:' + str(error), file=sys.stderr)
        sys.exit(1)
    print('COMPLETION_OBSERVER_OK:' + args.case + '; adapter provenance still requires review')
