//! Read-only prototype ABI. Its tags are not transaction wire assignments.
use crate::{
    context::PublicContext,
    decode::{decode_bundle, EncodedAction, EncodedBundle},
    validate_proof_shape, FixedVerifier, KeyConstructionFailed,
};
use orchard::bundle::BundleVersion;
use std::{mem, panic::catch_unwind, slice, sync::OnceLock};

#[repr(C)]
pub struct VerifyRequest {
    pub abi_version: u32,
    pub profile: u32,
    pub context: u32,
    pub flags: u8,
    pub value_balance: i64,
    pub principal_hi: u64,
    pub principal_lo: u64,
    pub fee_hi: u64,
    pub fee_lo: u64,
    pub anchor: [u8; 32],
    pub sighash: [u8; 32],
    pub binding_signature: [u8; 64],
    pub actions: *const EncodedAction,
    pub action_count: usize,
    pub proof: *const u8,
    pub proof_bytes: usize,
    pub max_actions: usize,
    pub max_proof_bytes: usize,
}

#[repr(u32)]
#[derive(Debug, PartialEq, Eq)]
pub enum AbiStatus {
    Ok = 0,
    Arguments = 1,
    Decode = 2,
    Verify = 3,
    Key = 4,
    Panic = 5,
}

fn context(request: &VerifyRequest) -> Result<PublicContext, AbiStatus> {
    let amount = (u128::from(request.principal_hi) << 64) | u128::from(request.principal_lo);
    let fee = (u128::from(request.fee_hi) << 64) | u128::from(request.fee_lo);
    match request.context {
        0 if amount == 0 => Ok(PublicContext::Transfer { fee }),
        1 => Ok(PublicContext::Unshield { amount, fee }),
        2 if fee == 0 => Ok(PublicContext::ShieldClaim { amount }),
        3 if fee == 0 => Ok(PublicContext::WithdrawalRefund { amount }),
        4 if fee == 0 => Ok(PublicContext::Genesis { amount }),
        5 if fee == 0 => Ok(PublicContext::PrivateFeeDistribution { amount }),
        _ => Err(AbiStatus::Arguments),
    }
}

fn bounded_span<T>(pointer: *const T, count: usize) -> bool {
    !pointer.is_null()
        && (pointer as usize) % mem::align_of::<T>() == 0
        && count.checked_mul(mem::size_of::<T>()).is_some_and(|bytes| {
            bytes <= isize::MAX as usize && (pointer as usize).checked_add(bytes).is_some()
        })
}

static VERIFIER: OnceLock<Result<FixedVerifier, KeyConstructionFailed>> = OnceLock::new();

#[cfg(test)]
std::thread_local! {
    static INJECT_UNWIND: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

unsafe fn verify(request: *const VerifyRequest) -> Result<(), AbiStatus> {
    #[cfg(test)]
    INJECT_UNWIND.with(|flag| {
        if flag.replace(false) {
            panic!("injected ABI verification unwind");
        }
    });
    if !bounded_span(request, 1) {
        return Err(AbiStatus::Arguments);
    }
    // The caller guarantees this initialized allocation remains readable throughout the call.
    let request = unsafe { &*request };
    if request.abi_version != 0 || request.profile != 1 {
        return Err(AbiStatus::Arguments);
    }
    let context = context(request)?;
    validate_proof_shape(
        request.action_count,
        request.proof_bytes,
        request.max_actions,
        request.max_proof_bytes,
    )
    .map_err(|_| AbiStatus::Arguments)?;
    if !bounded_span(request.actions, request.action_count)
        || !bounded_span(request.proof, request.proof_bytes)
    {
        return Err(AbiStatus::Arguments);
    }
    // Numeric bounds do not prove allocation validity; that remains the caller's contract.
    let actions = unsafe { slice::from_raw_parts(request.actions, request.action_count) };
    let proof = unsafe { slice::from_raw_parts(request.proof, request.proof_bytes) };
    let bundle = decode_bundle(
        &EncodedBundle {
            profile: BundleVersion::orchard_v2(),
            flags: request.flags,
            value_balance: request.value_balance,
            anchor: request.anchor,
            actions,
            proof,
            binding_signature: request.binding_signature,
        },
        request.max_actions,
        request.max_proof_bytes,
    )
    .map_err(|_| AbiStatus::Decode)?;
    let verifier = VERIFIER.get_or_init(FixedVerifier::new).as_ref().map_err(|_| AbiStatus::Key)?;
    verifier
        .verify_in_context(
            &bundle,
            context,
            &request.sighash,
            request.max_actions,
            request.max_proof_bytes,
        )
        .map_err(|_| AbiStatus::Verify)
}

fn contain_unwind(f: impl FnOnce() -> Result<(), AbiStatus> + std::panic::UnwindSafe) -> u32 {
    match catch_unwind(f) {
        Ok(Ok(())) => AbiStatus::Ok as u32,
        Ok(Err(error)) => error as u32,
        Err(_) => AbiStatus::Panic as u32,
    }
}

/// Verify borrowed public fields without retaining pointers or transferring ownership.
///
/// # Safety
/// Non-null pointers must refer to initialized, aligned allocations readable for
/// the supplied lengths and must not be mutated or freed until this call returns.
/// Numeric/null checks cannot validate arbitrary pointers. No unwinding panic
/// crosses the ABI; process aborts, OOM and invalid caller memory are not recoverable.
#[no_mangle]
pub unsafe extern "C" fn uno_crypto_verify_v0(request: *const VerifyRequest) -> u32 {
    contain_unwind(|| unsafe { verify(request) })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn abi_catches_verification_unwind() {
        INJECT_UNWIND.with(|flag| flag.set(true));
        assert_eq!(unsafe { uno_crypto_verify_v0(std::ptr::null()) }, AbiStatus::Panic as u32);
        assert_eq!(unsafe { uno_crypto_verify_v0(std::ptr::null()) }, AbiStatus::Arguments as u32);
    }
    #[test]
    fn abi_contains_unwind_and_rejects_invalid_spans() {
        assert_eq!(mem::size_of::<EncodedAction>(), 884);
        #[cfg(target_pointer_width = "64")]
        {
            assert_eq!(mem::size_of::<VerifyRequest>(), 232);
            assert_eq!(mem::offset_of!(VerifyRequest, value_balance), 16);
            assert_eq!(mem::offset_of!(VerifyRequest, actions), 184);
        }
        assert_eq!(contain_unwind(|| panic!("injected verifier unwind")), AbiStatus::Panic as u32);
        assert_eq!(unsafe { uno_crypto_verify_v0(std::ptr::null()) }, AbiStatus::Arguments as u32);
        let byte = 0u8;
        assert!(bounded_span(&byte, 1));
        assert!(!bounded_span(&byte, usize::MAX));
        assert!(!bounded_span(usize::MAX as *const u8, 1));
    }
}
