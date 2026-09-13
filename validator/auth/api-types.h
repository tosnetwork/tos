// Generated from the frozen method table.
#pragma once
#include "types.h"
namespace tos::auth {
inline Result<bool> validate_api_binary(std::uint8_t method, bool response, bool error, std::span<const std::uint8_t> raw) {
  if(method<1 || method>15)return Error{"method"};
  if(raw.size()>2000000)return Error{"api-binary-bound"};
  if(error){auto v=decode<ApiError>(raw);if(!v.ok())return v.error();return true;}
  switch(method){
    case 1: if(response){auto v=decode<Capabilities>(raw);if(!v.ok())return v.error();}else{auto v=decode<CapabilitiesRequest>(raw);if(!v.ok())return v.error();}break;
    case 2: if(response){auto v=decode<Key>(raw);if(!v.ok())return v.error();}else{auto v=decode<PublicRequest>(raw);if(!v.ok())return v.error();}break;
    case 3: if(response){auto v=decode<PrepareResult>(raw);if(!v.ok())return v.error();}else{auto v=decode<PrepareRequest>(raw);if(!v.ok())return v.error();}break;
    case 4: if(response){auto v=decode<StageResult>(raw);if(!v.ok())return v.error();}else{auto v=decode<StageRequest>(raw);if(!v.ok())return v.error();}break;
    case 5: if(response){auto v=decode<SignResult>(raw);if(!v.ok())return v.error();}else{auto v=decode<SignRequest>(raw);if(!v.ok())return v.error();}break;
    case 6: if(response){auto v=decode<RequestState>(raw);if(!v.ok())return v.error();}else{auto v=decode<ResultRequest>(raw);if(!v.ok())return v.error();}break;
    case 7: if(response){auto v=decode<RetireResult>(raw);if(!v.ok())return v.error();}else{auto v=decode<RetireRequest>(raw);if(!v.ok())return v.error();}break;
    case 8: if(response){auto v=decode<ProfileResult>(raw);if(!v.ok())return v.error();}else{auto v=decode<GetProfileRequest>(raw);if(!v.ok())return v.error();}break;
    case 9: if(response){auto v=decode<PolicyResult>(raw);if(!v.ok())return v.error();}else{auto v=decode<GetPolicyRequest>(raw);if(!v.ok())return v.error();}break;
    case 10: if(response){auto v=decode<RegistryResult>(raw);if(!v.ok())return v.error();}else{auto v=decode<GetRegistryRequest>(raw);if(!v.ok())return v.error();}break;
    case 11: if(response){auto v=decode<KeyResult>(raw);if(!v.ok())return v.error();}else{auto v=decode<GetKeyRequest>(raw);if(!v.ok())return v.error();}break;
    case 12: if(response){auto v=decode<CertificateResult>(raw);if(!v.ok())return v.error();}else{auto v=decode<GetCertificateRequest>(raw);if(!v.ok())return v.error();}break;
    case 13: if(response){auto v=decode<VerifyResult>(raw);if(!v.ok())return v.error();}else{auto v=decode<VerifyCertificateRequest>(raw);if(!v.ok())return v.error();}break;
    case 14: if(response){auto v=decode<ChunkResult>(raw);if(!v.ok())return v.error();}else{auto v=decode<ChunkRequest>(raw);if(!v.ok())return v.error();}break;
    case 15: if(response){auto v=decode<PutChunkResult>(raw);if(!v.ok())return v.error();}else{auto v=decode<PutChunkRequest>(raw);if(!v.ok())return v.error();}break;
  }
  return true;
}
}
