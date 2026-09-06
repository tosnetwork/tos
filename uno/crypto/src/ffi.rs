//! Read-only prototype ABI. Its tags are not transaction wire assignments.
use crate::{
    context::PublicContext,
    decode::{decode_bundle, EncodedAction, EncodedBundle},
    validate_proof_shape, FixedVerifier, KeyConstructionFailed,
};
use orchard::bundle::BundleVersion;
use std::{mem, panic::catch_unwind, slice, sync::{Mutex, OnceLock}};

pub const UNO_CRYPTO_ABI_VERSION: u32 = 0;
pub const UNO_CRYPTO_FIXED_PROFILE: u32 = 1;
pub const UNO_TRANSFER: u32 = 0;
pub const UNO_UNSHIELD: u32 = 1;
pub const UNO_SHIELD_CLAIM: u32 = 2;
pub const UNO_WITHDRAWAL_REFUND: u32 = 3;
pub const UNO_GENESIS: u32 = 4;
pub const UNO_PRIVATE_FEE_DISTRIBUTION: u32 = 5;

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

#[allow(non_camel_case_types)]
#[repr(u32)]
#[derive(Debug, PartialEq, Eq)]
pub enum AbiStatus {
    UNO_CRYPTO_OK = 0,
    UNO_CRYPTO_ARGUMENTS = 1,
    UNO_CRYPTO_DECODE = 2,
    UNO_CRYPTO_VERIFY = 3,
    UNO_CRYPTO_KEY = 4,
    UNO_CRYPTO_PANIC = 5,
}

fn context(request: &VerifyRequest) -> Result<PublicContext, AbiStatus> {
    let amount = (u128::from(request.principal_hi) << 64) | u128::from(request.principal_lo);
    let fee = (u128::from(request.fee_hi) << 64) | u128::from(request.fee_lo);
    match request.context {
        UNO_TRANSFER if amount == 0 => Ok(PublicContext::Transfer { fee }),
        UNO_UNSHIELD => Ok(PublicContext::Unshield { amount, fee }),
        UNO_SHIELD_CLAIM if fee == 0 => Ok(PublicContext::ShieldClaim { amount }),
        UNO_WITHDRAWAL_REFUND if fee == 0 => Ok(PublicContext::WithdrawalRefund { amount }),
        UNO_GENESIS if fee == 0 => Ok(PublicContext::Genesis { amount }),
        UNO_PRIVATE_FEE_DISTRIBUTION if fee == 0 => Ok(PublicContext::PrivateFeeDistribution { amount }),
        _ => Err(AbiStatus::UNO_CRYPTO_ARGUMENTS),
    }
}

pub(crate) fn bounded_span<T>(pointer: *const T, count: usize) -> bool {
    !pointer.is_null()
        && (pointer as usize) % mem::align_of::<T>() == 0
        && count.checked_mul(mem::size_of::<T>()).is_some_and(|bytes| {
            bytes <= isize::MAX as usize && (pointer as usize).checked_add(bytes).is_some()
        })
}

struct RetryingOnce<T> {
    value: OnceLock<T>,
    initializing: Mutex<()>,
}

impl<T> RetryingOnce<T> {
    const fn new() -> Self {
        Self { value: OnceLock::new(), initializing: Mutex::new(()) }
    }

    fn get_or_try_init(&self, build: impl FnOnce() -> Result<T, KeyConstructionFailed>)
        -> Result<&T, KeyConstructionFailed>
    {
        if let Some(value) = self.value.get() {
            return Ok(value);
        }
        // Serialize expensive construction, but never cache failure. The lock
        // protects initialization only; a published value is immutable.
        let _guard = match self.initializing.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        if let Some(value) = self.value.get() {
            return Ok(value);
        }
        let value = build()?;
        Ok(self.value.get_or_init(|| value))
    }
}

static VERIFIER: RetryingOnce<FixedVerifier> = RetryingOnce::new();

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
        return Err(AbiStatus::UNO_CRYPTO_ARGUMENTS);
    }
    // The caller guarantees this initialized allocation remains readable throughout the call.
    let request = unsafe { &*request };
    if request.abi_version != UNO_CRYPTO_ABI_VERSION || request.profile != UNO_CRYPTO_FIXED_PROFILE {
        return Err(AbiStatus::UNO_CRYPTO_ARGUMENTS);
    }
    let context = context(request)?;
    validate_proof_shape(
        request.action_count,
        request.proof_bytes,
        request.max_actions,
        request.max_proof_bytes,
    )
    .map_err(|_| AbiStatus::UNO_CRYPTO_ARGUMENTS)?;
    if !bounded_span(request.actions, request.action_count)
        || !bounded_span(request.proof, request.proof_bytes)
    {
        return Err(AbiStatus::UNO_CRYPTO_ARGUMENTS);
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
    .map_err(|_| AbiStatus::UNO_CRYPTO_DECODE)?;
    let verifier = VERIFIER.get_or_try_init(FixedVerifier::new).map_err(|_| AbiStatus::UNO_CRYPTO_KEY)?;
    verifier
        .verify_in_context(
            &bundle,
            context,
            &request.sighash,
            request.max_actions,
            request.max_proof_bytes,
        )
        .map_err(|_| AbiStatus::UNO_CRYPTO_VERIFY)
}

pub(crate) fn contain_unwind(f: impl FnOnce() -> Result<(), AbiStatus> + std::panic::UnwindSafe) -> u32 {
    match catch_unwind(f) {
        Ok(Ok(())) => AbiStatus::UNO_CRYPTO_OK as u32,
        Ok(Err(error)) => error as u32,
        Err(_) => AbiStatus::UNO_CRYPTO_PANIC as u32,
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
    fn verifier_construction_failure_is_retryable() {
        let cache = RetryingOnce::<FixedVerifier>::new();
        assert!(cache.get_or_try_init(|| Err(KeyConstructionFailed)).is_err());
        let key = cache.get_or_try_init(FixedVerifier::new).expect("retry constructs the fixed verifier");
        let again = cache.get_or_try_init(|| panic!("successful construction must be cached"))
            .expect("cached verifier");
        assert!(std::ptr::eq(key, again));
    }

    #[test]
    fn initializer_unwind_does_not_poison_retries() {
        let cache = RetryingOnce::<u32>::new();
        assert!(catch_unwind(|| cache.get_or_try_init(|| panic!("injected construction unwind"))).is_err());
        assert_eq!(*cache.get_or_try_init(|| Ok(7)).expect("retry after unwind"), 7);
    }

    #[test]
    fn concurrent_initializers_publish_once() {
        let cache = RetryingOnce::<u32>::new();
        let calls = std::sync::atomic::AtomicUsize::new(0);
        std::thread::scope(|scope| {
            for _ in 0..8 {
                scope.spawn(|| {
                    assert_eq!(*cache.get_or_try_init(|| {
                        calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        Ok(9)
                    }).expect("shared initialization"), 9);
                });
            }
        });
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    }
    #[test]
    fn abi_catches_verification_unwind() {
        INJECT_UNWIND.with(|flag| flag.set(true));
        assert_eq!(unsafe { uno_crypto_verify_v0(std::ptr::null()) }, AbiStatus::UNO_CRYPTO_PANIC as u32);
        assert_eq!(unsafe { uno_crypto_verify_v0(std::ptr::null()) }, AbiStatus::UNO_CRYPTO_ARGUMENTS as u32);
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
        assert_eq!(contain_unwind(|| panic!("injected verifier unwind")), AbiStatus::UNO_CRYPTO_PANIC as u32);
        assert_eq!(unsafe { uno_crypto_verify_v0(std::ptr::null()) }, AbiStatus::UNO_CRYPTO_ARGUMENTS as u32);
        let byte = 0u8;
        assert!(bounded_span(&byte, 1));
        assert!(!bounded_span(&byte, usize::MAX));
        assert!(!bounded_span(usize::MAX as *const u8, 1));
    }
}
