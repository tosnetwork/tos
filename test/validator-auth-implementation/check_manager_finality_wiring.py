"""Require manager finality to be durable, exact, restart-recovered and group-gating."""
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
CPP=ROOT/'validator/manager.cpp'
HPP=ROOT/'validator/manager.hpp'

def section(text: str, begin: str, end: str) -> str:
    start=text.index(begin); stop=text.index(end,start)
    return text[start:stop]

def replace_in(text: str, begin: str, end: str, old: str, new: str='') -> str:
    region=section(text,begin,end)
    edited=region.replace(old,new,1)
    if edited==region:
        raise RuntimeError('negative-control-no-edit '+old)
    return text.replace(region,edited,1)

def verify(text: str, header: str) -> None:
    finality=section(text,'td::actor::Task<> ValidatorManagerImpl::new_block_finality_broadcast',
                     'void ValidatorManagerImpl::add_shard_block_description')
    if finality.index('accept_validator_auth_finality_receipt') <= finality.index('if (status.is_error())'):
        raise ValueError('receipt-before-native-check')
    for token in ('get_next_validator_set(finality.block_id.shard_full()',
                  'get_validator_set(finality.block_id.shard_full()',
                  'build_validator_auth_finality_receipt(', 'finality.sig_set'):
        if token not in finality: raise ValueError('finality-'+token)

    refresh=section(text,'void ValidatorManagerImpl::refresh_validator_auth_finalized_head',
                    'void ValidatorManagerImpl::accept_validator_auth_finality_receipt')
    for token in ('encode_manager_finality_journal(', 'update_validator_auth_finality_journal'):
        if token not in refresh: raise ValueError('persist-'+token)
    written=section(text,'void ValidatorManagerImpl::validator_auth_finality_journal_written',
                    'void ValidatorManagerImpl::retry_validator_auth_finality_journal')
    if 'publish_validator_auth_finalized_head' not in written:
        raise ValueError('journal-ack-does-not-publish')

    chain=section(text,'void ValidatorManagerImpl::establish_validator_auth_chain',
                  'void ValidatorManagerImpl::started')
    for token in ('ManagerFinalizedHeadSource::create(chain.value(), opts_->zero_block_id(), zero_state)',
                  'NativeFinalizedHeadEstablisher::create(chain.value(), *finalized_source.value())',
                  'get_validator_auth_finality_journal'):
        if token not in chain: raise ValueError('bootstrap-'+token)

    recovery=section(text,'void ValidatorManagerImpl::got_validator_auth_finality_journal',
                     'void ValidatorManagerImpl::maybe_finish_validator_auth_finality_recovery')
    for token in ('decode_manager_finality_journal', 'get_shard_state_from_db_short(',
                  'note_verified(receipt.value())'):
        if token not in recovery: raise ValueError('recovery-'+token)

    applied=section(text,'void ValidatorManagerImpl::validator_auth_applied_block_ready',
                    'void ValidatorManagerImpl::fail_validator_auth_finality_recovery')
    for token in ('get_block_data_from_db_short(', 'block->data()',
                  'validator_auth_finalized_source_->note_applied(id, std::move(raw), std::move(state))'):
        if token not in applied: raise ValueError('applied-'+token)

    ready=section(header,'bool validator_auth_ready() const {',
                  'void publish_validator_auth_finalized_head')
    if 'validator_auth_chain_ && validator_auth_finality_ready_' not in ready:
        raise ValueError('ready-does-not-require-durable-finality')
    if 'return validator_auth_ready() && static_cast<bool>(validator_auth_session_store_);' not in ready:
        raise ValueError('groups-ready-does-not-compose-finality')

    catchup=section(text,'void ValidatorManagerImpl::maybe_finish_validator_auth_finality_recovery',
                    'std::string ValidatorManagerImpl::validator_auth_session_store_path')
    if 'last_masterchain_seqno_ < validator_auth_finalized_anchor_->seqno_' not in catchup:
        raise ValueError('missing-manager-catch-up-barrier')

    group=section(text,'// P0 is genesis-activated.',
                  'if (destroyed_validator_sessions_.contains(val_group_id))')
    if 'if (!validator_auth_groups_ready())' not in group:
        raise ValueError('groups-do-not-wait-for-durable-finality')

def main() -> None:
    text=CPP.read_text(); header=HPP.read_text()
    verify(text,header)
    probes=[
        ('cpp','td::actor::Task<> ValidatorManagerImpl::new_block_finality_broadcast',
         'void ValidatorManagerImpl::add_shard_block_description',
         'accept_validator_auth_finality_receipt(receipt.move_as_ok());'),
        ('cpp','void ValidatorManagerImpl::refresh_validator_auth_finalized_head',
         'void ValidatorManagerImpl::accept_validator_auth_finality_receipt',
         'encode_manager_finality_journal('),
        ('cpp','void ValidatorManagerImpl::validator_auth_finality_journal_written',
         'void ValidatorManagerImpl::retry_validator_auth_finality_journal',
         'publish_validator_auth_finalized_head(std::move(anchor), std::move(state));'),
        ('cpp','void ValidatorManagerImpl::establish_validator_auth_chain',
         'void ValidatorManagerImpl::started','get_validator_auth_finality_journal'),
        ('cpp','void ValidatorManagerImpl::got_validator_auth_finality_journal',
         'void ValidatorManagerImpl::maybe_finish_validator_auth_finality_recovery',
         'decode_manager_finality_journal'),
        ('cpp','void ValidatorManagerImpl::validator_auth_applied_block_ready',
         'void ValidatorManagerImpl::fail_validator_auth_finality_recovery','block->data()'),
        ('cpp','void ValidatorManagerImpl::maybe_finish_validator_auth_finality_recovery',
         'std::string ValidatorManagerImpl::validator_auth_session_store_path',
         'last_masterchain_seqno_ < validator_auth_finalized_anchor_->seqno_'),
        ('cpp','// P0 is genesis-activated.','if (destroyed_validator_sessions_.contains(val_group_id))',
         'if (!validator_auth_groups_ready())'),
    ]
    for _,begin,end,token in probes:
        changed=replace_in(text,begin,end,token,'/* removed */')
        try: verify(changed,header)
        except ValueError: pass
        else: raise RuntimeError('negative-control-survived '+token)

    hchanged=replace_in(header,'bool validator_auth_ready() const {',
                        'void publish_validator_auth_finalized_head',
                        'validator_auth_chain_ && validator_auth_finality_ready_','validator_auth_chain_')
    try: verify(text,hchanged)
    except ValueError: pass
    else: raise RuntimeError('negative-control-survived durable-finality-ready')

    print('PASS: manager finality is durable and exact before validator groups can use it')

if __name__=='__main__':
    main()
