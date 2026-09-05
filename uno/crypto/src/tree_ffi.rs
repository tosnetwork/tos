//! Borrowed tree transition ABI; no retained pointers or allocated return buffers.
use crate::{
    ffi::{bounded_span, contain_unwind, AbiStatus, UNO_CRYPTO_ABI_VERSION, UNO_CRYPTO_FIXED_PROFILE},
    tree::{FrontierSnapshot, NoteTree},
};

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TreeFrontier {
    pub next_position: u64,
    pub leaf: [u8; 32],
    pub ommer_count: u64,
    pub ommers: [[u8; 32]; 32],
}

#[repr(C)]
pub struct TreeRequest {
    pub abi_version: u32,
    pub profile: u32,
    pub frontier: *const TreeFrontier,
    pub commitments: *const [u8; 32],
    pub commitment_count: usize,
    pub max_commitments: usize,
    pub reserved_leaves: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TreeResult {
    pub frontier: TreeFrontier,
    pub root: [u8; 32],
}

#[cfg(test)]
std::thread_local! {
    static FAIL_BEFORE_PUBLISH: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

// Called only after bounded_span proves both numeric ranges cannot wrap.
fn overlaps<A, B>(a: *const A, count: usize, b: *const B) -> bool {
    let start = a as usize;
    let end = start + count * std::mem::size_of::<A>();
    let other = b as usize;
    start < other + std::mem::size_of::<B>() && other < end
}

unsafe fn transition(request: *const TreeRequest, output: *mut TreeResult) -> Result<(), AbiStatus> {
    if !bounded_span(request, 1) || !bounded_span(output, 1) || overlaps(request, 1, output) {
        return Err(AbiStatus::UNO_CRYPTO_ARGUMENTS);
    }
    let request = unsafe { &*request };
    if request.abi_version != UNO_CRYPTO_ABI_VERSION || request.profile != UNO_CRYPTO_FIXED_PROFILE
        || request.commitment_count > request.max_commitments
        || !bounded_span(request.frontier, 1) || overlaps(request.frontier, 1, output)
        || (request.commitment_count != 0 &&
            (!bounded_span(request.commitments, request.commitment_count)
             || overlaps(request.commitments, request.commitment_count, output)))
    {
        return Err(AbiStatus::UNO_CRYPTO_ARGUMENTS);
    }
    let input = unsafe { &*request.frontier };
    if input.ommer_count > 32 {
        return Err(AbiStatus::UNO_CRYPTO_DECODE);
    }
    let count = input.ommer_count as usize;
    if input.ommers[count..].iter().any(|node| *node != [0; 32])
        || (input.next_position == 0 && input.leaf != [0; 32])
    {
        return Err(AbiStatus::UNO_CRYPTO_DECODE);
    }
    let snapshot = FrontierSnapshot {
        next_position: input.next_position,
        leaf: (input.next_position != 0).then_some(input.leaf),
        ommers: input.ommers[..count].to_vec(),
    };
    let tree = NoteTree::restore(&snapshot).map_err(|_| AbiStatus::UNO_CRYPTO_DECODE)?;
    let commitments = if request.commitment_count == 0 { &[] } else {
        unsafe { std::slice::from_raw_parts(request.commitments, request.commitment_count) }
    };
    let next = tree.append_batch(commitments, request.reserved_leaves)
        .map_err(|_| AbiStatus::UNO_CRYPTO_DECODE)?;
    let snapshot = next.snapshot();
    let mut frontier = TreeFrontier {
        next_position: snapshot.next_position,
        leaf: snapshot.leaf.unwrap_or([0; 32]),
        ommer_count: snapshot.ommers.len() as u64,
        ommers: [[0; 32]; 32],
    };
    frontier.ommers[..snapshot.ommers.len()].copy_from_slice(&snapshot.ommers);
    let result = TreeResult { frontier, root: next.root() };
    #[cfg(test)]
    FAIL_BEFORE_PUBLISH.with(|flag| {
        if flag.replace(false) { panic!("injected tree publication unwind"); }
    });
    // No caller memory is written until parsing, append and root hashing finish.
    unsafe { output.write(result) };
    Ok(())
}

/// Restore a canonical frontier and stage ordered commitment append into caller storage.
///
/// # Safety
/// Inputs must be aligned, initialized, readable for their declared lengths and
/// immutable until return. Output must be aligned and writable for one TreeResult,
/// and must not overlap any input. Null commitments are allowed only at count zero.
/// Output is unchanged on nonzero status. No pointer is retained. Numeric checks
/// do not establish allocation validity; aborts/OOM/invalid memory are unrecoverable.
#[no_mangle]
pub unsafe extern "C" fn uno_crypto_tree_append_v0(request: *const TreeRequest, output: *mut TreeResult) -> u32 {
    contain_unwind(|| unsafe { transition(request, output) })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn panic_and_numeric_span_failure_preserve_output() {
        let frontier = TreeFrontier { next_position: 0, leaf: [0; 32], ommer_count: 0, ommers: [[0; 32]; 32] };
        let mut request = TreeRequest {
            abi_version: UNO_CRYPTO_ABI_VERSION, profile: UNO_CRYPTO_FIXED_PROFILE,
            frontier: &frontier, commitments: std::ptr::null(), commitment_count: 0,
            max_commitments: 0, reserved_leaves: 0,
        };
        let sentinel = TreeResult { frontier, root: [0xa5; 32] };
        let mut output = sentinel;
        FAIL_BEFORE_PUBLISH.with(|flag| flag.set(true));
        assert_eq!(unsafe { uno_crypto_tree_append_v0(&request, &mut output) }, AbiStatus::UNO_CRYPTO_PANIC as u32);
        assert_eq!(output, sentinel);
        let leaf = [[0; 32]];
        request.commitments = leaf.as_ptr();
        request.commitment_count = usize::MAX;
        request.max_commitments = usize::MAX;
        assert_eq!(unsafe { uno_crypto_tree_append_v0(&request, &mut output) }, AbiStatus::UNO_CRYPTO_ARGUMENTS as u32);
        assert_eq!(output, sentinel);
        request.commitment_count = 0;
        assert_eq!(unsafe { uno_crypto_tree_append_v0(&request, &mut output) }, AbiStatus::UNO_CRYPTO_OK as u32);
        assert_ne!(output.root, sentinel.root);
        assert_eq!(output.frontier, frontier);
    }
}
