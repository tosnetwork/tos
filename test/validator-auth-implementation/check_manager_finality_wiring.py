"""Require manager finality to join verified receipts to exact applied bytes/state."""
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];PATH=ROOT/'validator/manager.cpp'
def verify(text):
 finality=text[text.index('td::actor::Task<> ValidatorManagerImpl::new_block_finality_broadcast'):text.index('void ValidatorManagerImpl::add_shard_block_description')]
 if finality.index('accept_validator_auth_finality_receipt')<=finality.index('if (status.is_error())'):raise ValueError('receipt-before-native-check')
 for t in ('get_next_validator_set(finality.block_id.shard_full()','get_validator_set(finality.block_id.shard_full()','build_validator_auth_finality_receipt(','finality.sig_set'):
  if t not in finality:raise ValueError('finality-'+t)
 chain=text[text.index('void ValidatorManagerImpl::establish_validator_auth_chain'):text.index('void ValidatorManagerImpl::started')]
 for t in ('ManagerFinalizedHeadSource::create(chain.value(), opts_->zero_block_id(), zero_state)','NativeFinalizedHeadEstablisher::create(chain.value(), *finalized_source.value())','initial_head = finalized_establisher.value()->establish()','note_validator_auth_applied_masterchain_head()'):
  if t not in chain:raise ValueError('bootstrap-'+t)
 applied=text[text.index('void ValidatorManagerImpl::validator_auth_applied_block_ready'):text.index('void ValidatorManagerImpl::establish_validator_auth_chain')]
 for t in ('get_block_data_from_db_short(','block->data()','validator_auth_finalized_source_->note_applied(id, std::move(raw), std::move(state))'):
  if t not in applied:raise ValueError('applied-'+t)
 mc=text[text.index('void ValidatorManagerImpl::new_masterchain_block() {'):]
 if 'note_validator_auth_applied_masterchain_head();' not in mc[:500]:raise ValueError('installed-tip-not-fed')
def main():
 text=PATH.read_text();verify(text)
 for token in ('accept_validator_auth_finality_receipt(receipt.move_as_ok());','ManagerFinalizedHeadSource::create(chain.value(), opts_->zero_block_id(), zero_state)','get_block_data_from_db_short(','block->data()','validator_auth_finalized_source_->note_applied(id, std::move(raw), std::move(state))','note_validator_auth_applied_masterchain_head();'):
  changed=text.replace(token,'/* removed */',1)
  if changed==text:raise RuntimeError('negative-control-no-edit '+token)
  try:verify(changed)
  except ValueError:pass
  else:raise RuntimeError('negative-control-survived '+token)
 print('PASS: manager finalized head joins native finality to exact applied block bytes/state')
if __name__=='__main__':main()
