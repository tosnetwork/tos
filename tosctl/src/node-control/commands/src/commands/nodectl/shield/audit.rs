/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! The proving material a spend needs and the audit that qualifies it: the
//! finished phase-2 ceremony directory and the phase-1 slice its starting
//! key is rebuilt from. Both are named on the command line or, failing that,
//! by an environment variable an installation sets; an explicit argument
//! always wins. Whatever names them, the material is audited in full and its
//! verifying key held to the pin, every time.
//!
//! `tosctl shield audit-ceremony` runs that audit alone, without a chain, an
//! instance or funds, so an installation can be checked for what it proves
//! with. It proves the artifacts; whether a pool or a network accepts them is
//! a different question, answered by a verified head at spend time.

use anyhow::Context;
use colored::Colorize;
use shielded_pool_ceremony::audit::Audited;
use shielded_pool_ceremony::record::{self, Directory};
use std::ffi::OsString;
use std::path::{Path, PathBuf};

/// The environment variable an installation names the ceremony directory in.
pub const CEREMONY_DIR_VARIABLE: &str = "TOSCTL_SHIELD_CEREMONY_DIR";
/// The environment variable an installation names the phase-1 slice in.
pub const PHASE1_DIR_VARIABLE: &str = "TOSCTL_SHIELD_PHASE1_DIR";

/// The directories a proving command reads its material from.
#[derive(clap::Args, Clone, Debug, Default)]
pub struct Material {
    /// The finished phase-2 ceremony directory the proving key is read from.
    /// Its whole transcript is audited on every spend [env:
    /// TOSCTL_SHIELD_CEREMONY_DIR, used when the flag is absent]
    #[arg(long)]
    pub(super) ceremony_dir: Option<PathBuf>,
    /// The phase-1 slice directory the audit rebuilds the ceremony's starting
    /// key from (the slice bytes and their provenance record) [env:
    /// TOSCTL_SHIELD_PHASE1_DIR, used when the flag is absent]
    #[arg(long)]
    pub(super) phase1_dir: Option<PathBuf>,
}

/// Both directories, resolved.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Resolved {
    pub ceremony_dir: PathBuf,
    pub phase1_dir: PathBuf,
}

impl Material {
    /// The directories, from the arguments first and the environment second.
    pub fn resolve(&self) -> anyhow::Result<Resolved> {
        resolve(
            self.ceremony_dir.as_deref(),
            std::env::var_os(CEREMONY_DIR_VARIABLE),
            self.phase1_dir.as_deref(),
            std::env::var_os(PHASE1_DIR_VARIABLE),
        )
    }
}

/// An argument wins; an environment variable stands in for an absent one; an
/// empty variable names nothing. Neither present is an error that says both
/// ways to name the directory.
pub(super) fn resolve(
    ceremony_flag: Option<&Path>,
    ceremony_env: Option<OsString>,
    phase1_flag: Option<&Path>,
    phase1_env: Option<OsString>,
) -> anyhow::Result<Resolved> {
    Ok(Resolved {
        ceremony_dir: one("--ceremony-dir", CEREMONY_DIR_VARIABLE, ceremony_flag, ceremony_env)?,
        phase1_dir: one("--phase1-dir", PHASE1_DIR_VARIABLE, phase1_flag, phase1_env)?,
    })
}

fn one(
    flag: &str,
    variable: &str,
    given: Option<&Path>,
    from_env: Option<OsString>,
) -> anyhow::Result<PathBuf> {
    if let Some(path) = given {
        return Ok(path.to_path_buf());
    }
    match from_env {
        Some(value) if !value.is_empty() => Ok(PathBuf::from(value)),
        _ => anyhow::bail!(
            "no directory named: pass {flag} <DIR>, or set {variable} (an installation sets it to \
             the material it ships)"
        ),
    }
}

/// The material, audited in full: the ceremony directory's record and key
/// agree, the phase-1 slice is present, its starting key is rebuilt and the
/// contribution chain verified against it, the ceremony is finished, and its
/// verifying key is the one this client is pinned to. Cheap structural
/// refusals come first so a wrong directory is reported in a second, not
/// after minutes of rebuilding.
pub(super) fn audit_material(material: &Resolved) -> anyhow::Result<(Directory, Audited)> {
    let (pin_hex, _) = super::spend::ceremony_vk_pin()?;
    for (what, path) in [
        ("ceremony directory", &material.ceremony_dir),
        ("phase-1 directory", &material.phase1_dir),
    ] {
        let meta =
            std::fs::metadata(path).with_context(|| format!("the {what} {}", path.display()))?;
        anyhow::ensure!(meta.is_dir(), "the {what} {} is not a directory", path.display());
    }
    let directory = Directory::at(&material.ceremony_dir);
    anyhow::ensure!(
        directory.exists(),
        "{} holds no ceremony record",
        material.ceremony_dir.display()
    );
    let record =
        directory.read_record().map_err(|error| anyhow::anyhow!("the ceremony record: {error}"))?;
    let key_bytes = std::fs::read(material.ceremony_dir.join(record::KEY_FILE))
        .with_context(|| format!("the proving key {}", record::KEY_FILE))?;
    let key_digest = record::digest_of(&key_bytes);
    anyhow::ensure!(
        key_digest == record.key_sha256,
        "the proving key {} hashes to {key_digest} and the record says {}; the two files do not \
         describe the same ceremony",
        record::KEY_FILE,
        record.key_sha256
    );
    shielded_pool_ceremony::committed::load_slice(&material.phase1_dir)
        .map_err(|error| anyhow::anyhow!("the phase-1 slice: {error}"))?;
    eprintln!(
        "{} auditing the ceremony transcript in {} against the phase-1 slice in {} (minutes; \
         every spend pays for this)",
        "note:".bold(),
        material.ceremony_dir.display(),
        material.phase1_dir.display()
    );
    let audited = shielded_pool_prover::audit_ceremony_from(&material.phase1_dir, &directory)
        .map_err(|error| anyhow::anyhow!("ceremony audit: {error}"))?;
    anyhow::ensure!(
        audited.is_finished(),
        "the ceremony in {} is not finished: it is not closed \
         by a beacon, and nothing is proven with an unfinished key",
        material.ceremony_dir.display()
    );
    anyhow::ensure!(
        audited.vk_sha256() == pin_hex,
        "the audited ceremony's verifying key is {} and this client spends only with {pin_hex}",
        audited.vk_sha256()
    );
    Ok((directory, audited))
}

#[derive(clap::Args, Clone)]
#[command(about = "Audit the proving material an installation ships, without a chain")]
pub struct AuditCeremonyCmd {
    #[command(flatten)]
    material: Material,
}

impl AuditCeremonyCmd {
    pub fn run(&self) -> anyhow::Result<()> {
        let resolved = self.material.resolve()?;
        let started = std::time::Instant::now();
        let (_, audited) = audit_material(&resolved)?;
        let record = audited.record();
        println!(
            "{} the ceremony in {} is finished and its proving key is the one this client spends \
             with",
            "OK".green().bold(),
            resolved.ceremony_dir.display()
        );
        println!(
            "  Phase-1 slice:   {} ({})",
            record.phase1_transcript, record.phase1_slice_sha256
        );
        println!("  Starting key:    {}", record.starting_key_sha256);
        println!("  Proving key:     {}", record.key_sha256);
        println!("  Verifying key:   {} (pinned)", audited.vk_sha256());
        println!("  Audited in:      {:.1?}", started.elapsed());
        println!(
            "This proves the artifacts in those directories. Whether a pool verifies against this \
             key, and on which network, is read from a verified head at spend time."
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(path: &str) -> Option<&Path> {
        Some(Path::new(path))
    }

    #[test]
    fn an_argument_wins_the_environment_stands_in_and_nothing_is_refused_by_name() {
        let both = resolve(p("/c"), Some("/env-c".into()), p("/p"), Some("/env-p".into()))
            .expect("arguments");
        assert_eq!(both, Resolved { ceremony_dir: "/c".into(), phase1_dir: "/p".into() });
        let from_env = resolve(None, Some("/env-c".into()), None, Some("/env-p".into()))
            .expect("the environment");
        assert_eq!(
            from_env,
            Resolved { ceremony_dir: "/env-c".into(), phase1_dir: "/env-p".into() }
        );
        let mixed = resolve(p("/c"), None, None, Some("/env-p".into())).expect("mixed");
        assert_eq!(mixed, Resolved { ceremony_dir: "/c".into(), phase1_dir: "/env-p".into() });
        let error = resolve(None, None, p("/p"), None).err().expect("no ceremony dir");
        assert!(
            error.to_string().contains("--ceremony-dir")
                && error.to_string().contains(CEREMONY_DIR_VARIABLE),
            "{error}"
        );
        let error = resolve(p("/c"), None, None, Some("".into())).err().expect("empty variable");
        assert!(error.to_string().contains("--phase1-dir"), "{error}");
    }

    /// The committed material in this checkout.
    fn committed() -> Resolved {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../..");
        Resolved {
            ceremony_dir: root.join("artifacts/phase2-ceremony-2/ceremony"),
            phase1_dir: root.join("artifacts/phase1"),
        }
    }

    /// The expensive, positive audit runs in release builds only (the VM
    /// check and the prover's own tests); these are the refusals that come
    /// first and cost nothing.
    #[test]
    fn wrong_material_is_refused_before_anything_is_rebuilt() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()
            .expect("tempdir");
        let good = committed();

        let missing = Resolved { ceremony_dir: root.path().join("none"), ..good.clone() };
        let error = audit_material(&missing).err().expect("missing directory");
        assert!(error.to_string().contains("ceremony directory"), "{error}");

        let file = root.path().join("a-file");
        std::fs::write(&file, b"x").expect("write");
        let not_a_dir = Resolved { phase1_dir: file, ..good.clone() };
        let error = audit_material(&not_a_dir).err().expect("a file");
        assert!(error.to_string().contains("is not a directory"), "{error}");

        let empty = root.path().join("empty");
        std::fs::create_dir(&empty).expect("mkdir");
        let no_record = Resolved { ceremony_dir: empty.clone(), ..good.clone() };
        let error = audit_material(&no_record).err().expect("no record");
        assert!(error.to_string().contains("holds no ceremony record"), "{error}");
        let no_slice = Resolved { phase1_dir: empty, ..good.clone() };
        let error = audit_material(&no_slice).err().expect("no slice");
        assert!(error.to_string().contains("the phase-1 slice"), "{error}");

        // One byte of the proving key flipped: the record's digest refuses it
        // before the starting key is rebuilt.
        let flipped = root.path().join("flipped");
        std::fs::create_dir(&flipped).expect("mkdir");
        for name in ["beacon.bin", "ceremony.json", "contributions.bin", "key.bin"] {
            std::fs::copy(good.ceremony_dir.join(name), flipped.join(name)).expect("copy");
            // The committed material may be read-only (a store path is); the copy is ours.
            std::fs::set_permissions(flipped.join(name), std::fs::Permissions::from_mode(0o600))
                .expect("writable copy");
        }
        let mut key = std::fs::read(flipped.join("key.bin")).expect("key");
        if let Some(last) = key.last_mut() {
            *last ^= 1;
        }
        std::fs::write(flipped.join("key.bin"), key).expect("write");
        let started = std::time::Instant::now();
        let error = audit_material(&Resolved { ceremony_dir: flipped, ..good })
            .err()
            .expect("a flipped key");
        assert!(error.to_string().contains("the proving key"), "{error}");
        assert!(started.elapsed().as_secs() < 30, "refused before rebuilding the starting key");
    }
}
