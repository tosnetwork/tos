"""Require manager session admission and consensus owner handoff to be one path."""
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
M=(ROOT/'validator/manager.cpp').read_text()
B=(ROOT/'validator/consensus/bridge.cpp').read_text()
BUS=(ROOT/'validator/consensus/bus.h').read_text()

def verify(m=M,b=B,bus=BUS):
    helper=m[m.index('ValidatorManagerImpl::validator_auth_session_identity_input'):
             m.index('void ValidatorManagerImpl::establish_validator_auth_chain')]
    for token in (
        'opts_->get_vertical_seqno(anchor.seqno_)',
        'get_block_data_bounded',
        'NativeSessionCommitteeAdmission',
        'CommittedNativeSession::restart',
        'session-commitment-missing',
        'CommittedNativeSession::commit_new',
        'selected.epoch.native_session_id != it->second.expected_manager_id',
        'release_if_terminated',
    ):
        if token not in helper: raise ValueError('helper-'+token)
    active=m[m.index('// P0 is genesis-activated.'):
             m.index('if (destroyed_validator_sessions_.contains(val_group_id))')]
    for token in ('ensure_validator_auth_session(', 'get_maximal_vertical_seqno()',
                  'refusing unsafe local catchain session-id rewrite'):
        if token not in active: raise ValueError('active-'+token)
    tentative=m[m.index('auto get_or_make_next_group ='):m.index('active_validator_groups_master_')]
    if '!validator_auth_sessions_.contains(id)' not in tentative:
        raise ValueError('tentative-group-not-gated')
    owner=m[m.index('void ValidatorManagerImpl::get_validator_auth_session_owner'):
            m.index('void ValidatorManagerImpl::establish_validator_auth_chain')]
    if 'promise.set_value(it->second.owner)' not in owner:
        raise ValueError('manager-owner-not-returned')
    if 'get_validator_auth_session_owner' not in b or 'authenticated_session' not in bus:
        raise ValueError('consensus-owner-not-consumed')

def main():
    verify()
    for token in (
        'opts_->get_vertical_seqno(anchor.seqno_)',
        'get_block_data_bounded',
        'CommittedNativeSession::restart',
        'CommittedNativeSession::commit_new',
        'selected.epoch.native_session_id != it->second.expected_manager_id',
        'release_if_terminated',
        '!validator_auth_sessions_.contains(id)',
        'promise.set_value(it->second.owner)',
    ):
        changed=M.replace(token,'/* removed */',1)
        try: verify(m=changed)
        except ValueError: pass
        else: raise RuntimeError('negative control survived '+token)
    print('PASS: manager admits, commits, retains and hands one authenticated session owner to consensus')

if __name__=='__main__': main()
