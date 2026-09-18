#include "validator-auth-finality-store.h"
namespace tos::validator {
namespace { constexpr td::Slice key(){return td::Slice{"tos.state.validator_auth_finality_journal.v1"};} }
td::Status store_validator_auth_finality_journal(td::KeyValue& kv,td::Slice value){
 if(value.empty()||value.size()>validator_auth_finality_journal_max_bytes)return td::Status::Error("validator-auth finality journal bound");
 TRY_STATUS(kv.begin_write_batch());auto status=kv.set(key(),value);if(status.is_error()){kv.abort_write_batch().ignore();return status;}return kv.commit_write_batch();
}
td::Result<td::BufferSlice> load_validator_auth_finality_journal(td::KeyValue& kv){
 std::string value;TRY_RESULT(found,kv.get(key(),value));if(found==td::KeyValue::GetStatus::NotFound)return td::BufferSlice{};
 if(value.empty()||value.size()>validator_auth_finality_journal_max_bytes)return td::Status::Error("validator-auth finality journal bound");
 return td::BufferSlice{value};
}
}  // namespace tos::validator
