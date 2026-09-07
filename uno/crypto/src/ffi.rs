//! Versioned, borrowed kernel ABI. This is not transaction wire or admission policy.
use std::{mem, panic::catch_unwind, slice};

pub const UNO_CRYPTO_ABI_VERSION: u32 = 1;
pub const UNO_RELATION_SEND: u32 = 1;
pub const UNO_RELATION_COLLECT: u32 = 2;

#[allow(non_camel_case_types)]
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AbiStatus {
    UNO_CRYPTO_OK = 0,
    UNO_CRYPTO_ARGUMENTS = 1,
    UNO_CRYPTO_DECODE = 2,
    UNO_CRYPTO_VERIFY = 3,
    UNO_CRYPTO_KEY = 4,
    UNO_CRYPTO_PANIC = 5,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct KernelLimits {
    pub max_balance: u64,
    pub max_value: u64,
    pub max_collect: usize,
    pub max_context_bytes: usize,
    pub max_proof_bytes: usize,
}

#[repr(C)]
pub struct VerifyRequest {
    pub abi_version: u32,
    pub relation: u32,
    pub limits: KernelLimits,
    pub context: *const u8,
    pub context_bytes: usize,
    pub points: *const [u8; 32],
    pub point_count: usize,
    pub receipt_ids: *const [u8; 32],
    pub receipt_count: usize,
    pub commitments: *const [u8; 32],
    pub commitment_count: usize,
    pub responses: *const [u8; 32],
    pub response_count: usize,
    pub proof: *const u8,
    pub proof_bytes: usize,
}

pub(crate) fn bounded_span<T>(pointer: *const T, count: usize) -> bool {
    !pointer.is_null()
        && (pointer as usize) % mem::align_of::<T>() == 0
        && count.checked_mul(mem::size_of::<T>()).is_some_and(|bytes| {
            bytes <= isize::MAX as usize && (pointer as usize).checked_add(bytes).is_some()
        })
}

unsafe fn borrowed<'a, T>(pointer: *const T, count: usize) -> Result<&'a [T], AbiStatus> {
    if count == 0 { return Ok(&[]); }
    if !bounded_span(pointer, count) { return Err(AbiStatus::UNO_CRYPTO_ARGUMENTS); }
    // Allocation validity, initialization and lifetime are caller obligations.
    Ok(unsafe { slice::from_raw_parts(pointer, count) })
}

#[cfg(test)]
std::thread_local! {
    pub(crate) static INJECT_UNWIND: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

unsafe fn verify(request: *const VerifyRequest) -> Result<(), AbiStatus> {
    #[cfg(test)]
    INJECT_UNWIND.with(|flag| {
        if flag.replace(false) { panic!("injected verification unwind"); }
    });
    if !bounded_span(request, 1) { return Err(AbiStatus::UNO_CRYPTO_ARGUMENTS); }
    let r = unsafe { &*request };
    if r.abi_version != UNO_CRYPTO_ABI_VERSION {
        return Err(AbiStatus::UNO_CRYPTO_ARGUMENTS);
    }
    crate::relation::validate_limits(&r.limits)?;
    if r.receipt_count > r.limits.max_collect || r.context_bytes == 0
        || r.context_bytes > r.limits.max_context_bytes || r.proof_bytes > r.limits.max_proof_bytes {
        return Err(AbiStatus::UNO_CRYPTO_DECODE);
    }
    let (points, equations, witnesses, m) = crate::relation::shapes(r.relation, r.receipt_count)?;
    if r.point_count != points || r.commitment_count != equations
        || r.response_count != witnesses || r.proof_bytes != crate::relation::range_size(m)? {
        return Err(AbiStatus::UNO_CRYPTO_DECODE);
    }
    crate::verify_relation(r.relation, &r.limits,
        unsafe { borrowed(r.context, r.context_bytes)? },
        unsafe { borrowed(r.points, r.point_count)? },
        unsafe { borrowed(r.receipt_ids, r.receipt_count)? },
        unsafe { borrowed(r.commitments, r.commitment_count)? },
        unsafe { borrowed(r.responses, r.response_count)? },
        unsafe { borrowed(r.proof, r.proof_bytes)? })
}

pub(crate) fn contain_unwind(f: impl FnOnce() -> Result<(), AbiStatus> + std::panic::UnwindSafe) -> u32 {
    match catch_unwind(f) {
        Ok(Ok(())) => AbiStatus::UNO_CRYPTO_OK as u32,
        Ok(Err(error)) => error as u32,
        Err(_) => AbiStatus::UNO_CRYPTO_PANIC as u32,
    }
}

/// Verify borrowed fields without retaining pointers or transferring ownership.
/// No result authorizes a state change or authenticates the context's provenance.
///
/// # Safety
/// Non-null nonempty pointers must refer to initialized, aligned, readable
/// allocations of the supplied lengths, unchanged until return. Numeric checks
/// cannot validate arbitrary allocations. Unwinding panics are contained;
/// process abort, allocator OOM abort and invalid caller memory are not recoverable.
#[no_mangle]
pub unsafe extern "C" fn uno_crypto_verify_v1(request: *const VerifyRequest) -> u32 {
    contain_unwind(|| unsafe { verify(request) })
}
