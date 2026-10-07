//! Process-local opaque state handles. Caller buffers must be valid for their
//! declared lengths. These calls do not authenticate chain observations or sign.
use crate::lms_fee_journal::{FeeJournal, ReservedLeaf};
use crate::lms_fee_schedule::FeeRoute;
use std::{
    collections::HashMap,
    path::Path,
    sync::{Mutex, MutexGuard, OnceLock, TryLockError},
};

const INVALID: i32 = -1;
const STATE: i32 = -2;
const BUSY: i32 = -3;
const INTERNAL: i32 = -4;
const CAPACITY: i32 = -5;
const MAX_SESSIONS: usize = 256;
const MAX_RESERVATIONS: usize = 1024;
const SIGNATURE_SIZE: usize = 2832;
pub type FeeVerify =
    unsafe extern "C" fn(*mut std::ffi::c_void, *const u8, u32, *const u8, *const u8, usize) -> i32;

#[derive(Default)]
struct Registry {
    next: u64,
    sessions: HashMap<u64, FeeJournal>,
    reservations: HashMap<u64, (u64, ReservedLeaf)>,
}
impl Registry {
    fn id(&mut self) -> Result<u64, i32> {
        self.next = self.next.checked_add(1).ok_or(CAPACITY)?;
        Ok(self.next)
    }
}
fn registry() -> &'static Mutex<Registry> {
    static REGISTRY: OnceLock<Mutex<Registry>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(Registry::default()))
}
fn lock(r: &Mutex<Registry>) -> Result<MutexGuard<'_, Registry>, i32> {
    r.try_lock().map_err(|error| match error {
        TryLockError::WouldBlock => BUSY,
        TryLockError::Poisoned(_) => INTERNAL,
    })
}
fn boundary(f: impl FnOnce() -> Result<(), i32>) -> i32 {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)) {
        Ok(Ok(())) => 0,
        Ok(Err(code)) => code,
        Err(_) => INTERNAL,
    }
}
unsafe fn array32(p: *const u8) -> Result<[u8; 32], i32> {
    if p.is_null() {
        return Err(INVALID);
    }
    // SAFETY: the C API requires 32 readable bytes for non-null array arguments.
    let bytes = unsafe { std::slice::from_raw_parts(p, 32) };
    bytes.try_into().map_err(|_| INVALID)
}

/// Open a route-bound, locked session. Every open enforces the restore barrier.
/// Output is zero on failure. Capacity is checked before any journal creation.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tos_fee_state_open(
    path: *const u8,
    path_size: usize,
    global_id: i32,
    network: *const u8,
    vault: *const u8,
    tree_id: *const u8,
    epoch0: u32,
    proven_time: u32,
    output: *mut u64,
) -> i32 {
    boundary(|| {
        if output.is_null() {
            return Err(INVALID);
        }
        unsafe { output.write(0) };
        if path.is_null() || path_size == 0 || path_size > 4096 {
            return Err(INVALID);
        }
        let bytes = unsafe { std::slice::from_raw_parts(path, path_size) };
        if bytes.contains(&0) {
            return Err(INVALID);
        }
        let path = std::str::from_utf8(bytes).map_err(|_| INVALID)?;
        let route = FeeRoute {
            global_id,
            network: unsafe { array32(network)? },
            vault: unsafe { array32(vault)? },
            tree_id: unsafe { array32(tree_id)? },
            epoch0,
        };
        let mut r = lock(registry())?;
        if r.sessions.len() >= MAX_SESSIONS {
            return Err(CAPACITY);
        }
        let id = r.id()?;
        let journal = FeeJournal::open(Path::new(path), route, proven_time).map_err(|_| STATE)?;
        r.sessions.insert(id, journal);
        unsafe { output.write(id) };
        Ok(())
    })
}

/// Capacity observation only. The returned leaf is not permission to sign.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tos_fee_state_preview(
    handle: u64,
    time: u32,
    chain_next: u32,
    output: *mut u32,
) -> i32 {
    boundary(|| {
        if output.is_null() {
            return Err(INVALID);
        }
        unsafe { output.write(u32::MAX) };
        let r = lock(registry())?;
        let journal = r.sessions.get(&handle).ok_or(INVALID)?;
        let plan = journal.preview(time, chain_next).map_err(|_| STATE)?;
        unsafe { output.write(plan.leaf) };
        Ok(())
    })
}

/// Durably bind an exact digest to the previewed leaf. A failure never yields a
/// reservation token. Tokens are local ownership receipts, not crypto approval.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tos_fee_state_reserve(
    handle: u64,
    time: u32,
    chain_next: u32,
    expected_leaf: u32,
    digest: *const u8,
    output: *mut u64,
) -> i32 {
    boundary(|| {
        if output.is_null() {
            return Err(INVALID);
        }
        unsafe { output.write(0) };
        let digest = unsafe { array32(digest)? };
        let mut r = lock(registry())?;
        if r.reservations.len() >= MAX_RESERVATIONS {
            return Err(CAPACITY);
        }
        if !r.sessions.contains_key(&handle) {
            return Err(INVALID);
        }
        let id = r.id()?;
        let journal = r.sessions.get_mut(&handle).ok_or(INVALID)?;
        let receipt =
            journal.reserve(time, chain_next, expected_leaf, digest).map_err(|_| STATE)?;
        r.reservations.insert(id, (handle, receipt));
        unsafe { output.write(id) };
        Ok(())
    })
}

/// Release the session and its in-memory tokens. Durable reservations remain
/// burned; reopening cannot restore current-slot continuity.
#[unsafe(no_mangle)]
pub extern "C" fn tos_fee_state_close(handle: u64) -> i32 {
    boundary(|| {
        let mut r = lock(registry())?;
        if r.sessions.remove(&handle).is_none() {
            return Err(INVALID);
        }
        r.reservations.retain(|_, (owner, _)| *owner != handle);
        Ok(())
    })
}

/// Verify with a trusted native primitive, then consume the reservation token
/// and persist immutable signature bytes. Verification failure burns the token.
/// Callback returns exactly 1 for valid; it must not unwind or use RPC verdicts.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tos_fee_state_cache_verified(
    handle: u64,
    token: u64,
    public_key: *const u8,
    signature: *const u8,
    size: usize,
    verify: Option<FeeVerify>,
    context: *mut std::ffi::c_void,
) -> i32 {
    boundary(|| {
        if public_key.is_null() || signature.is_null() || size != SIGNATURE_SIZE {
            return Err(INVALID);
        }
        let verify = verify.ok_or(INVALID)?;
        let key = unsafe { std::slice::from_raw_parts(public_key, 60) };
        let signature = unsafe { std::slice::from_raw_parts(signature, size) };
        let mut r = lock(registry())?;
        if !r.sessions.contains_key(&handle) {
            return Err(INVALID);
        }
        let owner = r.reservations.get(&token).ok_or(INVALID)?.0;
        if owner != handle {
            return Err(INVALID);
        }
        let (_, receipt) = r.reservations.remove(&token).ok_or(INVALID)?;
        let leaf = receipt.leaf();
        let digest = *receipt.intent_hash();
        if unsafe {
            verify(
                context,
                key.as_ptr(),
                leaf,
                digest.as_ptr(),
                signature.as_ptr(),
                signature.len(),
            )
        } != 1
        {
            return Err(STATE);
        }
        let journal = r.sessions.get_mut(&handle).ok_or(INVALID)?;
        journal.cache_signature(receipt, signature).map_err(|_| STATE)
    })
}

/// Load exact cached bytes and reverify before copying to caller output.
/// A miss never invokes a signer. Live route/expiry/consumption remain caller gates.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tos_fee_state_cached_verified(
    handle: u64,
    leaf: u32,
    digest: *const u8,
    public_key: *const u8,
    verify: Option<FeeVerify>,
    context: *mut std::ffi::c_void,
    output: *mut u8,
    size: usize,
) -> i32 {
    boundary(|| {
        if output.is_null() || size != SIGNATURE_SIZE {
            return Err(INVALID);
        }
        unsafe { std::ptr::write_bytes(output, 0, size) };
        if public_key.is_null() {
            return Err(INVALID);
        }
        let verify = verify.ok_or(INVALID)?;
        let digest = unsafe { array32(digest)? };
        let key = unsafe { std::slice::from_raw_parts(public_key, 60) };
        let mut r = lock(registry())?;
        let journal = r.sessions.get_mut(&handle).ok_or(INVALID)?;
        let signature = journal.cached_signature(leaf, digest).map_err(|_| STATE)?;
        if unsafe {
            verify(
                context,
                key.as_ptr(),
                leaf,
                digest.as_ptr(),
                signature.as_ptr(),
                signature.len(),
            )
        } != 1
        {
            return Err(STATE);
        }
        unsafe { std::ptr::copy_nonoverlapping(signature.as_ptr(), output, size) };
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::{ffi::OsStrExt, fs::PermissionsExt};
    static FFI_TEST: Mutex<()> = Mutex::new(());

    #[test]
    fn cache_tokens_are_single_use_and_export_is_reverified() -> anyhow::Result<()> {
        let _serial = FFI_TEST.lock().expect("isolated registry fixture");
        unsafe extern "C" fn valid(
            _: *mut std::ffi::c_void,
            _: *const u8,
            _: u32,
            _: *const u8,
            _: *const u8,
            _: usize,
        ) -> i32 {
            1
        }
        unsafe extern "C" fn invalid(
            _: *mut std::ffi::c_void,
            _: *const u8,
            _: u32,
            _: *const u8,
            _: *const u8,
            _: usize,
        ) -> i32 {
            0
        }
        let dir = tempfile::tempdir()?;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))?;
        let path = dir.path().as_os_str().as_bytes();
        let route = [1; 32];
        let digest = [9; 32];
        let key = [0; 60];
        let mut h = 0;
        assert_eq!(
            unsafe {
                tos_fee_state_open(
                    path.as_ptr(),
                    path.len(),
                    42,
                    route.as_ptr(),
                    route.as_ptr(),
                    route.as_ptr(),
                    100,
                    100,
                    &mut h,
                )
            },
            0
        );
        let mut token = 0;
        assert_eq!(unsafe { tos_fee_state_reserve(h, 3700, 0, 4, digest.as_ptr(), &mut token) }, 0);
        // Framing-only public fixture. Callback doubles are not crypto evidence.
        let mut sig = [0x55; SIGNATURE_SIZE];
        sig[..4].copy_from_slice(&0u32.to_be_bytes());
        sig[4..8].copy_from_slice(&4u32.to_be_bytes());
        sig[8..12].copy_from_slice(&3u32.to_be_bytes());
        sig[2188..2192].copy_from_slice(&8u32.to_be_bytes());
        let other_dir = tempfile::tempdir()?;
        std::fs::set_permissions(other_dir.path(), std::fs::Permissions::from_mode(0o700))?;
        let other_path = other_dir.path().as_os_str().as_bytes();
        let mut other = 0;
        assert_eq!(
            unsafe {
                tos_fee_state_open(
                    other_path.as_ptr(),
                    other_path.len(),
                    42,
                    route.as_ptr(),
                    route.as_ptr(),
                    route.as_ptr(),
                    100,
                    100,
                    &mut other,
                )
            },
            0
        );
        assert_eq!(
            unsafe {
                tos_fee_state_cache_verified(
                    other,
                    token,
                    key.as_ptr(),
                    sig.as_ptr(),
                    sig.len(),
                    Some(valid),
                    std::ptr::null_mut(),
                )
            },
            INVALID
        );
        assert_eq!(
            unsafe {
                tos_fee_state_cache_verified(
                    h,
                    token,
                    key.as_ptr(),
                    sig.as_ptr(),
                    sig.len(),
                    Some(valid),
                    std::ptr::null_mut(),
                )
            },
            0
        );
        assert_eq!(
            unsafe {
                tos_fee_state_cache_verified(
                    h,
                    token,
                    key.as_ptr(),
                    sig.as_ptr(),
                    sig.len(),
                    Some(valid),
                    std::ptr::null_mut(),
                )
            },
            INVALID
        );
        assert_eq!(tos_fee_state_close(other), 0);
        let mut output = [0xff; SIGNATURE_SIZE];
        assert_eq!(
            unsafe {
                tos_fee_state_cached_verified(
                    h,
                    4,
                    digest.as_ptr(),
                    key.as_ptr(),
                    Some(invalid),
                    std::ptr::null_mut(),
                    output.as_mut_ptr(),
                    output.len(),
                )
            },
            STATE
        );
        assert!(output.iter().all(|b| *b == 0));
        assert_eq!(
            unsafe {
                tos_fee_state_cached_verified(
                    h,
                    4,
                    digest.as_ptr(),
                    key.as_ptr(),
                    Some(valid),
                    std::ptr::null_mut(),
                    output.as_mut_ptr(),
                    output.len(),
                )
            },
            0
        );
        assert_eq!(output, sig);
        assert_eq!(unsafe { tos_fee_state_reserve(h, 3700, 0, 5, digest.as_ptr(), &mut token) }, 0);
        sig[4..8].copy_from_slice(&5u32.to_be_bytes());
        assert_eq!(
            unsafe {
                tos_fee_state_cache_verified(
                    h,
                    token,
                    key.as_ptr(),
                    sig.as_ptr(),
                    sig.len(),
                    Some(invalid),
                    std::ptr::null_mut(),
                )
            },
            STATE
        );
        assert_eq!(
            unsafe {
                tos_fee_state_cache_verified(
                    h,
                    token,
                    key.as_ptr(),
                    sig.as_ptr(),
                    sig.len(),
                    Some(valid),
                    std::ptr::null_mut(),
                )
            },
            INVALID
        );
        assert_eq!(tos_fee_state_close(h), 0);
        assert_eq!(
            unsafe {
                tos_fee_state_open(
                    path.as_ptr(),
                    path.len(),
                    42,
                    route.as_ptr(),
                    route.as_ptr(),
                    route.as_ptr(),
                    100,
                    3700,
                    &mut h,
                )
            },
            0
        );
        assert_eq!(
            unsafe {
                tos_fee_state_cached_verified(
                    h,
                    4,
                    digest.as_ptr(),
                    key.as_ptr(),
                    Some(valid),
                    std::ptr::null_mut(),
                    output.as_mut_ptr(),
                    output.len(),
                )
            },
            0
        );
        assert_eq!(&output[4..8], &4u32.to_be_bytes());
        assert_eq!(
            unsafe {
                tos_fee_state_cached_verified(
                    h,
                    5,
                    digest.as_ptr(),
                    key.as_ptr(),
                    Some(valid),
                    std::ptr::null_mut(),
                    output.as_mut_ptr(),
                    output.len(),
                )
            },
            STATE
        );
        assert!(output.iter().all(|b| *b == 0));
        assert_eq!(tos_fee_state_close(h), 0);
        Ok(())
    }

    #[test]
    fn contention_and_poisoning_have_distinct_failure_codes() {
        let local = Mutex::new(Registry::default());
        let held = local.lock().expect("local fixture mutex");
        assert!(matches!(lock(&local), Err(BUSY)));
        drop(held);
        let result = std::panic::catch_unwind(|| {
            let _held = local.lock().expect("fixture lock before panic");
            panic!("public fixture: uncertain state operation");
        });
        assert!(result.is_err());
        assert!(matches!(lock(&local), Err(INTERNAL)));
    }

    #[test]
    fn ffi_lifecycle_keeps_reservations_and_restore_barrier() -> anyhow::Result<()> {
        let _serial = FFI_TEST.lock().expect("isolated registry fixture");
        let dir = tempfile::tempdir()?;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))?;
        let path = dir.path().as_os_str().as_bytes();
        let network = [1; 32];
        let vault = [2; 32];
        let tree = [3; 32];
        let digest = [9; 32];
        let mut handle = 99;
        let open = |time, output: &mut u64| unsafe {
            tos_fee_state_open(
                path.as_ptr(),
                path.len(),
                42,
                network.as_ptr(),
                vault.as_ptr(),
                tree.as_ptr(),
                100,
                time,
                output,
            )
        };
        assert_eq!(open(100, &mut handle), 0);
        assert_ne!(handle, 0);
        let mut duplicate = 99;
        assert_eq!(open(100, &mut duplicate), STATE);
        assert_eq!(duplicate, 0);
        let mut leaf = 99;
        assert_eq!(unsafe { tos_fee_state_preview(handle, 100, 0, &mut leaf) }, STATE);
        assert_eq!(leaf, u32::MAX);
        assert_eq!(unsafe { tos_fee_state_preview(handle, 3700, 0, &mut leaf) }, 0);
        assert_eq!(leaf, 4);
        let mut receipt = 99;
        assert_eq!(
            unsafe { tos_fee_state_reserve(handle, 3700, 0, 5, digest.as_ptr(), &mut receipt) },
            STATE
        );
        assert_eq!(receipt, 0);
        assert_eq!(
            unsafe { tos_fee_state_reserve(handle, 3700, 0, leaf, digest.as_ptr(), &mut receipt) },
            0
        );
        assert_ne!(receipt, 0);
        assert_eq!(unsafe { tos_fee_state_preview(handle, 3700, 0, &mut leaf) }, 0);
        assert_eq!(leaf, 5);
        assert_eq!(tos_fee_state_close(handle), 0);
        assert_eq!(tos_fee_state_close(handle), INVALID);
        assert_eq!(unsafe { tos_fee_state_preview(handle, 7300, 0, &mut leaf) }, INVALID);
        assert_eq!(leaf, u32::MAX);
        let old = handle;
        assert_eq!(open(3700, &mut handle), 0);
        assert_ne!(handle, old);
        assert_eq!(unsafe { tos_fee_state_preview(handle, 3700, 0, &mut leaf) }, STATE);
        assert_eq!(unsafe { tos_fee_state_preview(handle, 7300, 0, &mut leaf) }, 0);
        assert_eq!(leaf, 8);
        assert_eq!(tos_fee_state_close(handle), 0);
        assert_eq!(unsafe { tos_fee_state_preview(0, 0, 0, std::ptr::null_mut()) }, INVALID);
        let mut output = 99;
        assert_eq!(
            unsafe {
                tos_fee_state_open(
                    std::ptr::null(),
                    1,
                    0,
                    network.as_ptr(),
                    vault.as_ptr(),
                    tree.as_ptr(),
                    100,
                    100,
                    &mut output,
                )
            },
            INVALID
        );
        assert_eq!(output, 0);
        Ok(())
    }
}
