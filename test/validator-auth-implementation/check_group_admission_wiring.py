"""Pin startup/retry and live-session liveness to the current manager path."""
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
MANAGER=ROOT/'validator/manager.cpp'

def section(text,begin,end):
    i=text.index(begin);j=text.index(end,i);return text[i:j]

def replace_in(text,begin,end,token):
    region=section(text,begin,end)
    changed=region.replace(token,'/* removed */',1)
    if changed==region: raise RuntimeError('negative-control-no-edit '+token)
    return text.replace(region,changed,1)

def verify(text):
    started=section(text,'void ValidatorManagerImpl::started(',
                    'void ValidatorManagerImpl::got_destroyed_validator_sessions')
    if 'if (validator_auth_required())' not in started:
        raise ValueError('inactive-startup-still-reads-zero-state')

    establish=section(text,'void ValidatorManagerImpl::establish_validator_auth_chain',
                      'void ValidatorManagerImpl::retry_validator_auth_chain')
    if 'if (!validator_auth_required())' not in establish:
        raise ValueError('inactive-establish-not-gated')
    if establish.index('if (!validator_auth_required())') > establish.index('get_zero_state_file'):
        raise ValueError('inactive-gate-after-zero-state-read')

    retry=section(text,'void ValidatorManagerImpl::retry_validator_auth_chain',
                  'void ValidatorManagerImpl::validator_auth_chain_retry_due')
    for token in ('if (!validator_auth_required())','validator_auth_chain_retry_.succeeded();'):
        if token not in retry: raise ValueError('inactive-retry-'+token)
    if retry.index('if (!validator_auth_required())') > retry.index('validator_auth_chain_retry_.failed()'):
        raise ValueError('inactive-retry-scheduled-before-gate')

    gate=section(text,'// P0 is genesis-activated.',
                 'if (destroyed_validator_sessions_.contains(val_group_id))')
    for token in (
        'live_same_session = validator_groups_.contains(val_group_id)',
        'authenticated_session_admission_required(',
        'validator_auth_groups_ready()',
        'validator_auth_admission_.defer_groups();',
        'ensure_validator_auth_session(',
    ):
        if token not in gate: raise ValueError('active-group-gate-'+token)
    if gate.index('authenticated_session_admission_required(') > gate.index('validator_auth_groups_ready()'):
        raise ValueError('live-session-bypass-after-transient-readiness-gate')

    admission=section(text,'void ValidatorManagerImpl::fail_validator_auth_session_admission',
                      'bool ValidatorManagerImpl::validator_auth_required')
    for token in ('validator_auth_session_refused_at_[session_id]',
                  'refused->second >= validator_auth_finalized_anchor_->seqno_',
                  'CommittedNativeSession::restart','CommittedNativeSession::commit_new'):
        if token not in admission: raise ValueError('session-admission-'+token)

    publish=section(text,'void ValidatorManagerImpl::publish_validator_auth_finalized_head',
                    'void ValidatorManagerImpl::validator_auth_finality_journal_written')
    for token in ('release_terminated_validator_auth_sessions();',
                  'validator_auth_admission_.create_deferred_groups(',
                  'update_shards();'):
        if token not in publish: raise ValueError('finalized-redrive-'+token)

    cleanup=section(text,'void ValidatorManagerImpl::got_pending_validator_consensus_db_cleanup',
                    'void ValidatorManagerImpl::sweep_destroyed_consensus_dbs')
    if 'validator_auth_admission_.cleanup_records_loaded();' not in cleanup:
        raise ValueError('cleanup-startup-barrier-missing')

def main():
    text=MANAGER.read_text();verify(text)
    probes=(
      ('void ValidatorManagerImpl::started(','void ValidatorManagerImpl::got_destroyed_validator_sessions',
       'if (validator_auth_required())'),
      ('void ValidatorManagerImpl::establish_validator_auth_chain','void ValidatorManagerImpl::retry_validator_auth_chain',
       'if (!validator_auth_required())'),
      ('void ValidatorManagerImpl::retry_validator_auth_chain','void ValidatorManagerImpl::validator_auth_chain_retry_due',
       'if (!validator_auth_required())'),
      ('// P0 is genesis-activated.','if (destroyed_validator_sessions_.contains(val_group_id))',
       'live_same_session = validator_groups_.contains(val_group_id)'),
      ('// P0 is genesis-activated.','if (destroyed_validator_sessions_.contains(val_group_id))',
       'authenticated_session_admission_required('),
      ('void ValidatorManagerImpl::publish_validator_auth_finalized_head',
       'void ValidatorManagerImpl::validator_auth_finality_journal_written',
       'validator_auth_admission_.create_deferred_groups('),
    )
    for begin,end,token in probes:
        changed=replace_in(text,begin,end,token)
        try: verify(changed)
        except ValueError: pass
        else: raise RuntimeError('negative-control-survived '+token)
    print('PASS: inactive chains do not poll auth state and live admitted sessions survive transient manager refusal')

if __name__=='__main__': main()
