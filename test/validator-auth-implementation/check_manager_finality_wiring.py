"""Require manager finality to be durable, exact, and restart-recovered before use."""
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
PATH=ROOT/'validator/manager.cpp'

def verify(text: str) -> None:
    finality=text[text.index('td::actor::Task<> ValidatorManagerImpl::new_block_finality_broadcast'):
                  text.index('void ValidatorManagerImpl::add_shard_block_description')]
    if finality.index('accept_validator_auth_finality_receipt') <= finality.index('if (status.is_error())'):
        raise ValueError('receipt-before-native-check')
    for token in ('get_next_validator_set(finality.block_id.shard_full()',
                  'get_validator_set(finality.block_id.shard_full()',
                  'build_validator_auth_finality_receipt(', 'finality.sig_set'):
        if token not in finality:
            raise ValueError('finality-'+token)

    refresh=text[text.index('void ValidatorManagerImpl::refresh_validator_auth_finalized_head'):
                 text.index('void ValidatorManagerImpl::accept_validator_auth_finality_receipt')]
    for token in ('encode_manager_finality_journal(', 'update_validator_auth_finality_journal'):
        if token not in refresh:
            raise ValueError('persist-'+token)
    written=text[text.index('void ValidatorManagerImpl::validator_auth_finality_journal_written'):
                 text.index('void ValidatorManagerImpl::retry_validator_auth_finality_journal')]
    if 'publish_validator_auth_finalized_head' not in written:
        raise ValueError('journal-ack-does-not-publish')

    chain=text[text.index('void ValidatorManagerImpl::establish_validator_auth_chain'):
               text.index('void ValidatorManagerImpl::started')]
    for token in ('ManagerFinalizedHeadSource::create(chain.value(), opts_->zero_block_id(), zero_state)',
                  'NativeFinalizedHeadEstablisher::create(chain.value(), *finalized_source.value())',
                  'get_validator_auth_finality_journal'):
        if token not in chain:
            raise ValueError('bootstrap-'+token)

    recovery=text[text.index('void ValidatorManagerImpl::got_validator_auth_finality_journal'):
                  text.index('void ValidatorManagerImpl::maybe_finish_validator_auth_finality_recovery')]
    for token in ('decode_manager_finality_journal', 'get_shard_state_from_db_short(',
                  'note_verified(receipt.value())'):
        if token not in recovery:
            raise ValueError('recovery-'+token)

    applied=text[text.index('void ValidatorManagerImpl::validator_auth_applied_block_ready'):
                 text.index('void ValidatorManagerImpl::fail_validator_auth_finality_recovery')]
    for token in ('get_block_data_from_db_short(', 'block->data()',
                  'validator_auth_finalized_source_->note_applied(id, std::move(raw), std::move(state))'):
        if token not in applied:
            raise ValueError('applied-'+token)

    if 'last_masterchain_seqno_ < validator_auth_finalized_anchor_->seqno_' not in text:
        raise ValueError('missing-manager-catch-up-barrier')
    group=text[text.index('if (tos::auth::native_session_binding_active'):text.index('if (destroyed_validator_sessions_.contains')]
    if 'if (!validator_auth_ready())' not in group:
        raise ValueError('groups-do-not-wait-for-durable-finality')

def main() -> None:
    text=PATH.read_text()
    verify(text)
    tokens=(
        'accept_validator_auth_finality_receipt(receipt.move_as_ok());',
        'encode_manager_finality_journal(',
        'update_validator_auth_finality_journal',
        'publish_validator_auth_finalized_head(std::move(anchor), std::move(state));',
        'get_validator_auth_finality_journal',
        'decode_manager_finality_journal',
        'get_shard_state_from_db_short(',
        'block->data()',
        'validator_auth_finalized_source_->note_applied(id, std::move(raw), std::move(state))',
        'last_masterchain_seqno_ < validator_auth_finalized_anchor_->seqno_',
        'if (!validator_auth_ready())',
    )
    for token in tokens:
        changed=text.replace(token,'/* removed */',1)
        if changed==text:
            raise RuntimeError('negative-control-no-edit '+token)
        try:
            verify(changed)
        except ValueError:
            pass
        else:
            raise RuntimeError('negative-control-survived '+token)
    print('PASS: manager finality is durable and exact before validator authority is exposed')

if __name__=='__main__':
    main()
