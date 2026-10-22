/*
 * Copyright (C) 2025-2026 TOS Blockchain Teams.
 * Licensed under the GNU General Public License v3.0.
 */

//! Shared source-tree discovery for contract compilation and genesis tooling.

use std::path::{Path, PathBuf};

fn source_root(path: &Path) -> Option<PathBuf> {
    if path.join("crypto/smartcont/stdlib.fc").is_file() && path.join("crypto/fift/lib").is_dir() {
        path.canonicalize().ok()
    } else {
        None
    }
}

fn resolve_tos_root(explicit: Option<&Path>, cwd: &Path, home: Option<&Path>) -> Option<PathBuf> {
    // An explicit source selection must not silently fall back to another tree.
    if let Some(path) = explicit {
        return source_root(path);
    }
    // Prefer the enclosing worktree, including package directories more than
    // four levels deep. Tool overrides do not require a local build directory.
    cwd.ancestors()
        .find_map(source_root)
        .or_else(|| home.and_then(|path| source_root(&path.join("tos"))))
}

/// Locate the TOS source tree and return its absolute, canonical path.
///
/// `TOS_ROOT` selects a source tree explicitly. Otherwise the enclosing checkout
/// takes precedence over `~/tos`. Discovery checks source files, independently
/// of `FUNC_PATH`, `FIFT_PATH` and `CREATE_STATE_PATH` binary overrides.
pub fn find_tos_root() -> Option<PathBuf> {
    let explicit = std::env::var_os("TOS_ROOT").map(PathBuf::from);
    let home = std::env::var_os("HOME").map(PathBuf::from);
    let cwd = std::env::current_dir().ok()?;
    resolve_tos_root(explicit.as_deref(), &cwd, home.as_deref())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tree(path: &Path) {
        std::fs::create_dir_all(path.join("crypto/smartcont")).unwrap();
        std::fs::create_dir_all(path.join("crypto/fift/lib")).unwrap();
        std::fs::write(path.join("crypto/smartcont/stdlib.fc"), "").unwrap();
    }

    #[test]
    fn source_root_prefers_enclosing_worktree_without_local_binaries() {
        let tmp = tempfile::tempdir().unwrap();
        let worktree = tmp.path().join("worktree");
        let home = tmp.path().join("home");
        tree(&worktree);
        tree(&home.join("tos"));
        let nested = worktree.join("tosctl/src/node-control/contracts/tests/deeper");
        std::fs::create_dir_all(&nested).unwrap();
        assert_eq!(
            resolve_tos_root(None, &nested, Some(&home)),
            Some(worktree.canonicalize().unwrap())
        );
    }

    #[test]
    fn explicit_source_root_wins_and_invalid_selection_does_not_fall_back() {
        let tmp = tempfile::tempdir().unwrap();
        let selected = tmp.path().join("selected");
        let enclosing = tmp.path().join("enclosing");
        tree(&selected);
        tree(&enclosing);
        assert_eq!(
            resolve_tos_root(Some(&selected), &enclosing, None),
            Some(selected.canonicalize().unwrap())
        );
        assert_eq!(resolve_tos_root(Some(&tmp.path().join("missing")), &enclosing, None), None);
    }

    #[test]
    fn source_root_uses_home_only_without_an_enclosing_tree() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        tree(&home.join("tos"));
        assert_eq!(
            resolve_tos_root(None, tmp.path(), Some(&home)),
            Some(home.join("tos").canonicalize().unwrap())
        );
    }
}
