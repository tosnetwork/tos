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

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::{ffi::OsStrExt, fs::PermissionsExt};

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
