//! Versioned, borrowed kernel ABI. This is not transaction wire or admission policy.
use std::{mem, panic::catch_unwind, slice};

pub const UNO_CRYPTO_ABI_VERSION: u32 = 1;
pub const UNO_BALANCE_ABI_VERSION: u32 = 2;
pub const UNO_RELATION_SEND: u32 = 1;
pub const UNO_RELATION_COLLECT: u32 = 2;
pub const UNO_POSSESSION_CONTEXT_BYTES: usize = 426;

/// Public registration context, not native struct bytes in the transcript.
/// The host independently matches these fields to the address and configuration.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct KeyPossessionRequestV2 {
    pub abi_version: u32,
    pub context: [u8; UNO_POSSESSION_CONTEXT_BYTES],
    pub global_id: i32,
    pub genesis_hash: [u8; 32],
    pub workchain_id: i32,
    pub account: [u8; 32],
    pub incarnation: [u8; 32],
    pub asset: [u8; 32],
    pub custody: [u8; 32],
    pub policy: [u8; 32],
    pub schema_version: u16,
    pub relation_profile: u16,
    pub proof_profile: u16,
    pub key_epoch: u32,
    pub public_key: [u8; 32],
    pub proof: [u8; 64],
}

/// Fixed-width authenticated closure statement; no caller-supplied challenge.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ClosurePossessionRequestV2 {
    pub abi_version: u32,
    pub context: [u8; UNO_POSSESSION_CONTEXT_BYTES],
    pub domain: [u8; 80],
    pub global_id: i32,
    pub genesis_hash: [u8; 32],
    pub workchain_id: i32,
    pub account: [u8; 32],
    pub incarnation: [u8; 32],
    pub asset: [u8; 32],
    pub custody: [u8; 32],
    pub policy: [u8; 32],
    pub schema_version: u16,
    pub relation_profile: u16,
    pub proof_profile: u16,
    pub key_epoch: u32,
    pub auth_nonce: u64,
    pub available_revision: u64,
    pub public_key: [u8; 32],
    pub commitment: [u8; 32],
    pub handle: [u8; 32],
    pub proof: [u8; 96],
}

/// Verify zero available and possession; not pending/obligation emptiness.
/// # Safety
/// Request must be initialized, aligned, readable and unchanged until return.
/// No pointer is retained; numeric checks cannot establish allocation validity.
#[no_mangle]
pub unsafe extern "C" fn uno_crypto_verify_closure_possession_v2(request: *const ClosurePossessionRequestV2) -> u32 {
    contain_unwind(|| {
        if !bounded_span(request, 1) { return Err(AbiStatus::UNO_CRYPTO_ARGUMENTS); }
        let request = unsafe { &*request };
        if request.abi_version != 2 { return Err(AbiStatus::UNO_CRYPTO_ARGUMENTS); }
        crate::closure_possession::verify(request)
    })
}

/// Verify registration possession, not a new balance relation.
///
/// # Safety
/// Request must be initialized, aligned, readable and unchanged until return.
/// No pointer is retained. Span checks cannot establish allocation validity.
#[no_mangle]
pub unsafe extern "C" fn uno_crypto_verify_key_possession_v2(request: *const KeyPossessionRequestV2) -> u32 {
    contain_unwind(|| {
        if !bounded_span(request, 1) { return Err(AbiStatus::UNO_CRYPTO_ARGUMENTS); }
        let request = unsafe { &*request };
        if request.abi_version != 2 { return Err(AbiStatus::UNO_CRYPTO_ARGUMENTS); }
        crate::key_possession::verify(request)
    })
}

// Retired ABI symbols reject without dereferencing the old, smaller request.
// Keeping rejection stubs prevents a linked old caller from selecting the
// transcript that did not bind the complete authenticated replay context.
#[no_mangle]
pub extern "C" fn uno_crypto_verify_key_possession_v1(_: *const std::ffi::c_void) -> u32 {
    AbiStatus::UNO_CRYPTO_ARGUMENTS as u32
}
#[no_mangle]
pub extern "C" fn uno_crypto_verify_closure_possession_v1(_: *const std::ffi::c_void) -> u32 {
    AbiStatus::UNO_CRYPTO_ARGUMENTS as u32
}

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
pub struct VerifyRequestV2 {
    pub abi_version: u32,
    pub relation: u32,
    pub limits: KernelLimits,
    pub domain: [u8; 80],
    pub fee: u64,
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

/// Dedicated D64 input: six balance points only. The three public transfer
/// points and P_B are constructed inside WithdrawalStatement, never supplied.
#[repr(C)]
pub struct WithdrawalVerifyRequestV1 {
    pub abi_version: u32,
    pub limits: KernelLimits,
    pub domain: [u8; 80],
    pub withdrawal_id: [u8; 32],
    pub attempt_id: [u8; 32],
    pub principal: u64,
    pub outward_fee: u64,
    pub return_reserve: u64,
    pub operation_fee: u64,
    pub balance_points: [[u8; 32]; 6],
    pub context: *const u8,
    pub context_bytes: usize,
    pub commitments: *const [u8; 32],
    pub commitment_count: usize,
    pub responses: *const [u8; 32],
    pub response_count: usize,
    pub proof: *const u8,
    pub proof_bytes: usize,
}

/// Borrowed host-owned buffers; all pointers must remain valid until return.
/// This verifies a statement, not authenticated fee/configuration provenance.
#[no_mangle]
pub unsafe extern "C" fn uno_crypto_verify_withdrawal_v1(request: *const WithdrawalVerifyRequestV1) -> u32 {
    contain_unwind(|| {
        if !bounded_span(request, 1) { return Err(AbiStatus::UNO_CRYPTO_ARGUMENTS); }
        let r = unsafe { &*request };
        if r.abi_version != 1 { return Err(AbiStatus::UNO_CRYPTO_ARGUMENTS); }
        crate::relation::validate_limits(&r.limits)?;
        if r.context_bytes != 566 || r.commitment_count != 8 || r.response_count != 6
            || r.proof_bytes != 864 || r.proof_bytes > r.limits.max_proof_bytes {
            return Err(AbiStatus::UNO_CRYPTO_DECODE);
        }
        let amounts = crate::withdrawal_statement::WithdrawalAmounts {
            principal: r.principal, outward_fee: r.outward_fee,
            return_reserve: r.return_reserve, operation_fee: r.operation_fee,
        };
        // Includes checked x+q+b before scalar conversion (D66).
        let statement = crate::withdrawal_statement::WithdrawalStatement::new(
            &r.limits, r.domain, r.withdrawal_id, r.attempt_id, amounts,
            unsafe { borrowed(r.context, r.context_bytes)? }, r.balance_points)?;
        statement.verify(&r.limits,
            unsafe { borrowed(r.commitments, r.commitment_count)? },
            unsafe { borrowed(r.responses, r.response_count)? },
            unsafe { borrowed(r.proof, r.proof_bytes)? })
    })
}

/// Fixed-width encoded public inputs. Numeric policy and domain provenance
/// must be resolved by the host; ABI version is not a network activation gate.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SystemEncryptionRequest {
    pub abi_version: u32,
    pub domain: [u8; 80],
    pub deposit_id: [u8; 32],
    pub recipient: [u8; 32],
    pub amount: u64,
}

/// D69 fixed-width request. origin_bytes is exactly 41 or 115; unused tail
/// bytes are zero. Canonical origin framing comes from the host codec.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SystemEncryptionRequestV2 {
    pub abi_version: u32,
    pub domain: [u8; 80],
    pub receipt_id: [u8; 32],
    pub recipient: [u8; 32],
    pub amount: u64,
    pub origin: [u8; 115],
    pub origin_bytes: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SystemCiphertext {
    pub commitment: [u8; 32],
    pub handle: [u8; 32],
}

unsafe fn system_ciphertext(request: *const SystemEncryptionRequest) -> Result<SystemCiphertext, AbiStatus> {
    #[cfg(test)]
    INJECT_UNWIND.with(|flag| {
        if flag.replace(false) { panic!("injected system encryption unwind"); }
    });
    if !bounded_span(request, 1) { return Err(AbiStatus::UNO_CRYPTO_ARGUMENTS); }
    let r = unsafe { &*request };
    if r.abi_version != UNO_CRYPTO_ABI_VERSION { return Err(AbiStatus::UNO_CRYPTO_ARGUMENTS); }
    let [commitment, handle] = crate::system_encryption::encrypt_encoded(
        &r.domain, &r.deposit_id, &r.recipient, r.amount)?;
    Ok(SystemCiphertext { commitment, handle })
}

/// Construct a public system ciphertext. Output is untouched unless successful.
///
/// # Safety
/// Request must be initialized and readable; output must be aligned, writable
/// and disjoint from request for the entire call. No pointer is retained.
/// Numeric span checks do not prove allocation validity. Pending-only use and
/// deposit authentication are host obligations, not implied by success.
#[no_mangle]
pub unsafe extern "C" fn uno_crypto_system_encrypt_v1(
    request: *const SystemEncryptionRequest, output: *mut SystemCiphertext) -> u32 {
    contain_unwind(|| {
        if !bounded_span(output, 1) { return Err(AbiStatus::UNO_CRYPTO_ARGUMENTS); }
        let ciphertext = unsafe { system_ciphertext(request)? };
        unsafe { output.write(ciphertext); }
        Ok(())
    })
}

/// Reconstruct and compare both canonical ciphertext components without writes.
///
/// # Safety
/// Non-null arguments must be initialized, aligned and readable for the call.
/// This call does not authorize issuance, bind an account or consume a message.
#[no_mangle]
pub unsafe extern "C" fn uno_crypto_system_verify_v1(
    request: *const SystemEncryptionRequest, supplied: *const SystemCiphertext) -> u32 {
    contain_unwind(|| {
        if !bounded_span(supplied, 1) { return Err(AbiStatus::UNO_CRYPTO_ARGUMENTS); }
        let expected = unsafe { system_ciphertext(request)? };
        if expected != unsafe { *supplied } { return Err(AbiStatus::UNO_CRYPTO_VERIFY); }
        Ok(())
    })
}

unsafe fn system_ciphertext_v2(request: *const SystemEncryptionRequestV2) -> Result<SystemCiphertext, AbiStatus> {
    if !bounded_span(request, 1) { return Err(AbiStatus::UNO_CRYPTO_ARGUMENTS); }
    let r = unsafe { &*request };
    let n = r.origin_bytes as usize;
    if r.abi_version != 2 || !matches!(n, 41 | 115) || r.origin[n..].iter().any(|&x| x != 0) {
        return Err(AbiStatus::UNO_CRYPTO_ARGUMENTS);
    }
    let [commitment, handle] = crate::system_encryption::encrypt_origin_encoded(
        &r.domain, &r.receipt_id, &r.origin[..n], &r.recipient, r.amount)?;
    Ok(SystemCiphertext { commitment, handle })
}
/// D69 construction; no host issuance or counter mutation is authorized.
/// # Safety
/// Same readable, aligned, disjoint request/output requirements as v1.
#[no_mangle]
pub unsafe extern "C" fn uno_crypto_system_encrypt_v2(
    request: *const SystemEncryptionRequestV2, output: *mut SystemCiphertext) -> u32 {
    contain_unwind(|| {
        if !bounded_span(output, 1) { return Err(AbiStatus::UNO_CRYPTO_ARGUMENTS); }
        let expected = unsafe { system_ciphertext_v2(request)? };
        unsafe { output.write(expected); }
        Ok(())
    })
}
/// D69 reconstruction and exact comparison of both ciphertext components.
/// # Safety
/// Same readable, aligned request/ciphertext requirements as v1.
#[no_mangle]
pub unsafe extern "C" fn uno_crypto_system_verify_v2(
    request: *const SystemEncryptionRequestV2, supplied: *const SystemCiphertext) -> u32 {
    contain_unwind(|| {
        if !bounded_span(supplied, 1) { return Err(AbiStatus::UNO_CRYPTO_ARGUMENTS); }
        let expected = unsafe { system_ciphertext_v2(request)? };
        if expected != unsafe { *supplied } { return Err(AbiStatus::UNO_CRYPTO_VERIFY); }
        Ok(())
    })
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

unsafe fn verify(request: *const VerifyRequestV2) -> Result<(), AbiStatus> {
    #[cfg(test)]
    INJECT_UNWIND.with(|flag| {
        if flag.replace(false) { panic!("injected verification unwind"); }
    });
    if !bounded_span(request, 1) { return Err(AbiStatus::UNO_CRYPTO_ARGUMENTS); }
    let r = unsafe { &*request };
    if r.abi_version != UNO_BALANCE_ABI_VERSION {
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
    crate::verify_relation(r.relation, &r.limits, &r.domain, r.fee,
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
pub unsafe extern "C" fn uno_crypto_verify_v2(request: *const VerifyRequestV2) -> u32 {
    contain_unwind(|| unsafe { verify(request) })
}
