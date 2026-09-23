/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! Where a contribution's randomness comes from.
//!
//! A phase-2 contribution is worth exactly as much as the secret behind it is
//! unguessable. Everything else in the ceremony is checkable -- a verifier can
//! prove that a participant multiplied `delta` by *something* they knew -- but
//! no check anywhere can tell that the something was drawn well. If a
//! participant's generator is predictable then their contribution is
//! predictable, and a ceremony is only as strong as its strongest participant,
//! so one good draw saves it and one bad draw simply does not help.
//!
//! That asymmetry is why this module is narrow on purpose:
//!
//! * the library offers **one** source, the operating system, and there is no
//!   seeded constructor anywhere in it. A test that wants a repeatable draw
//!   writes its own [`Entropy`] in the test crate, so the insecure path is
//!   never reachable from a binary this crate ships;
//! * participant-supplied material can only be **stirred in**, never
//!   substituted. [`Stirred`] hashes the operating system's bytes together
//!   with the participant's, so the result is unpredictable if *either* input
//!   was -- which is the only honest way to offer "bring your own entropy";
//! * a source that fails in the obvious way is refused rather than used. A
//!   read that returns a constant block is the shape a stubbed, unseeded or
//!   mis-wired source has, and it is worth a loud error even though a genuine
//!   generator produces such a block with probability far below anything else
//!   that could go wrong.
//!
//! What this module deliberately does **not** do is judge randomness. There is
//! no entropy estimator here and there should not be: a statistical test on
//! sixty-four bytes cannot distinguish a good generator from a keyed stream
//! cipher an adversary holds the key to, and offering one would invite
//! somebody to trust it.

use std::io::Read;

use crate::error::{Error, Result};

/// A source of unpredictable bytes.
///
/// Implementations outside this crate exist so tests can be repeatable. They
/// are not a production path and nothing in this crate constructs one.
pub trait Entropy {
    /// Fills `out` completely, or fails.
    ///
    /// A short read is an error, never a silently half-filled buffer: a
    /// partially filled buffer keeps its leading zeros and would make a secret
    /// far easier to guess than its length suggests.
    fn fill(&mut self, out: &mut [u8]) -> Result<()>;
}

/// The operating system's generator.
///
/// `/dev/urandom` rather than `getrandom(2)` for the same reason the phase-1
/// verifier reads it: no crate in this tree wraps the syscall, and a file read
/// has no version-dependent behaviour to get wrong. After boot the two are the
/// same pool.
///
/// This is the only [`Entropy`] this crate implements.
#[derive(Debug, Default, Clone, Copy)]
pub struct OperatingSystem;

impl Entropy for OperatingSystem {
    fn fill(&mut self, out: &mut [u8]) -> Result<()> {
        let mut file = std::fs::File::open("/dev/urandom")?;
        file.read_exact(out)?;
        refuse_a_constant_block(out)
    }
}

/// A block every byte of which is the same value is refused.
///
/// This catches the failures that actually happen -- a source wired to a zero
/// buffer, a mock left in place, a device that opened but returned nothing --
/// and it is not a randomness test. A working generator hits this for a
/// 64-byte draw with probability 256 / 2^512, which is smaller than the chance
/// of the machine being wrong about anything at all.
fn refuse_a_constant_block(bytes: &[u8]) -> Result<()> {
    match bytes.first() {
        Some(first) if bytes.len() > 1 && bytes.iter().all(|byte| byte == first) => {
            Err(Error::Entropy(format!(
                "the entropy source returned {} identical bytes; it is not delivering randomness",
                bytes.len()
            )))
        }
        _ => Ok(()),
    }
}

/// Domain separation for the stirring hash, so bytes drawn here can never
/// collide with bytes any other part of the ceremony derives.
const STIR_DOMAIN: &[u8] = b"TOS-SHIELDED-POOL-V1-PHASE2-ENTROPY-STIR";

/// An entropy source with extra material mixed into every draw.
///
/// The point is a participant who does not want to stake their contribution on
/// the machine's generator alone -- dice, a hardware token, a second machine.
/// The material is an *additional* input, never a replacement: each draw is a
/// hash of the inner source's fresh bytes together with the material and a
/// counter, so
///
/// * a compromised operating system generator is survived if the material was
///   unpredictable, and
/// * material an adversary chose, or watched, or later publishes, costs
///   nothing as long as the operating system's bytes were unpredictable.
///
/// The material itself is held in memory for the life of the source and wiped
/// when it is dropped, because a participant who typed a passphrase in expects
/// it to be as protected as the secret it helps produce.
pub struct Stirred<E: Entropy> {
    inner: E,
    material: Vec<u8>,
    counter: u64,
}

impl<E: Entropy> Stirred<E> {
    /// Mixes `material` into every draw from `inner`.
    ///
    /// The material is moved in and never copied out. There is no accessor for
    /// it and no `Debug`.
    pub fn new(inner: E, material: Vec<u8>) -> Result<Self> {
        if material.is_empty() {
            return Err(Error::Entropy(
                "no material to stir in; use the source on its own rather than pretending to \
                 strengthen it"
                    .into(),
            ));
        }
        Ok(Self { inner, material, counter: 0 })
    }
}

impl<E: Entropy> Entropy for Stirred<E> {
    fn fill(&mut self, out: &mut [u8]) -> Result<()> {
        use sha2::{Digest, Sha512};

        // Fresh bytes from the inner source for every block, so the counter is
        // a domain separator rather than the only thing that changes.
        //
        // `Zeroizing` rather than a wipe at the end, for the reason the draw
        // in `secret.rs` gives: the `?` on the next line is an early return,
        // and a wipe after the loop is skipped by exactly the path that took
        // it.
        let mut fresh = zeroize::Zeroizing::new([0u8; 64]);
        for block in out.chunks_mut(64) {
            self.inner.fill(fresh.as_mut())?;
            self.counter = self.counter.checked_add(1).ok_or_else(|| {
                Error::Entropy("this source has produced more blocks than it can count".into())
            })?;

            let mut hasher = Sha512::new();
            hasher.update(STIR_DOMAIN);
            hasher.update(self.counter.to_le_bytes());
            hasher.update(fresh.as_ref());
            hasher.update(&self.material);
            // The digest is derived from the material and is as sensitive as
            // it is, so it is wiped rather than left on the stack.
            let mut stirred = zeroize::Zeroizing::new([0u8; 64]);
            stirred.copy_from_slice(&hasher.finalize());
            block.copy_from_slice(&stirred[..block.len()]);
        }

        Ok(())
    }
}

impl<E: Entropy> Drop for Stirred<E> {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.material);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A source that hands back whatever it was told to, for the checks that
    /// are about the wrapper rather than about randomness.
    struct Fixed(Vec<u8>);

    impl Entropy for Fixed {
        fn fill(&mut self, out: &mut [u8]) -> Result<()> {
            for (slot, byte) in out.iter_mut().zip(self.0.iter().cycle()) {
                *slot = *byte;
            }
            Ok(())
        }
    }

    #[test]
    fn the_operating_system_delivers_and_does_not_repeat_itself() {
        let mut first = [0u8; 64];
        let mut second = [0u8; 64];
        OperatingSystem.fill(&mut first).expect("the system generator");
        OperatingSystem.fill(&mut second).expect("the system generator");
        assert_ne!(first, second, "two draws came back identical");
        assert!(first.iter().any(|byte| *byte != 0));
    }

    #[test]
    fn a_constant_block_is_refused() {
        assert!(refuse_a_constant_block(&[0u8; 64]).is_err(), "an all-zero block was accepted");
        assert!(refuse_a_constant_block(&[0xffu8; 64]).is_err(), "an all-ones block was accepted");
        // One byte says nothing either way, and neither does an empty read.
        assert!(refuse_a_constant_block(&[0u8]).is_ok());
        assert!(refuse_a_constant_block(&[]).is_ok());
        let mut mixed = [7u8; 64];
        mixed[31] = 8;
        assert!(refuse_a_constant_block(&mixed).is_ok());
    }

    /// The claim that makes [`Stirred`] worth having: if the inner source is
    /// broken -- here, stuck at a constant -- the output still moves, because
    /// it cannot be predicted from the material alone without the counter and
    /// the domain.
    ///
    /// This is the weaker half of the argument. The half that matters in
    /// production is the other way round and cannot be tested: material an
    /// adversary chose does not weaken a working system generator.
    #[test]
    fn material_survives_an_inner_source_that_is_stuck() {
        let mut source =
            Stirred::new(Fixed(vec![0x41]), b"dice rolls".to_vec()).expect("material to stir in");
        let mut first = [0u8; 64];
        let mut second = [0u8; 64];
        source.fill(&mut first).expect("a draw");
        source.fill(&mut second).expect("a draw");
        assert_ne!(first, second, "a stuck inner source produced a stuck output");
    }

    /// And the other direction: the same material with a different inner draw
    /// gives a different answer, so the material is not what the output is.
    #[test]
    fn the_inner_source_is_not_ignored() {
        let material = b"the same material both times".to_vec();
        let mut one = Stirred::new(Fixed(vec![1, 2, 3]), material.clone()).expect("material");
        let mut other = Stirred::new(Fixed(vec![9, 9, 8]), material).expect("material");
        let mut first = [0u8; 64];
        let mut second = [0u8; 64];
        one.fill(&mut first).expect("a draw");
        other.fill(&mut second).expect("a draw");
        assert_ne!(first, second, "the inner source made no difference to the output");
    }

    #[test]
    fn stirring_in_nothing_is_refused() {
        assert!(
            Stirred::new(OperatingSystem, Vec::new()).is_err(),
            "an empty material was accepted, which would look like protection and be none"
        );
    }

    /// A draw longer than one hash block is filled from several, each with its
    /// own fresh inner bytes -- not by repeating one block.
    #[test]
    fn a_long_draw_is_not_one_block_repeated() {
        let mut source = Stirred::new(Fixed(vec![0x5a]), b"material".to_vec()).expect("material");
        let mut out = [0u8; 192];
        source.fill(&mut out).expect("a draw");
        let (first, rest) = out.split_at(64);
        assert_ne!(first, &rest[..64], "block two repeats block one");
        assert_ne!(&rest[..64], &rest[64..], "block three repeats block two");
    }

    /// The material changes the answer.
    ///
    /// `material_survives_an_inner_source_that_is_stuck` does not establish
    /// this: the counter alone makes a stuck source produce varying output, so
    /// a version that never hashed the material at all passes it. Two sources
    /// identical but for their material are what tell them apart.
    #[test]
    fn the_material_changes_the_answer() {
        let mut one =
            Stirred::new(Fixed(vec![3, 1, 4]), b"first material".to_vec()).expect("material");
        let mut other =
            Stirred::new(Fixed(vec![3, 1, 4]), b"second material".to_vec()).expect("material");
        let mut first = [0u8; 64];
        let mut second = [0u8; 64];
        one.fill(&mut first).expect("a draw");
        other.fill(&mut second).expect("a draw");
        assert_ne!(first, second, "the material made no difference");
    }

    /// Every block gets its own read from the inner source.
    ///
    /// Reading once and varying only the counter would make a long draw an
    /// expansion of sixty-four bytes of entropy rather than a concatenation of
    /// several -- fine for a stream cipher, wrong for a source whose whole job
    /// is to keep delivering unpredictability. The previous test cannot see
    /// the difference, because the counter alone makes the blocks differ.
    #[test]
    fn each_block_reads_the_inner_source_again() {
        struct Counting {
            reads: std::rc::Rc<std::cell::Cell<usize>>,
        }
        impl Entropy for Counting {
            fn fill(&mut self, out: &mut [u8]) -> Result<()> {
                self.reads.set(self.reads.get() + 1);
                out.fill(self.reads.get() as u8);
                Ok(())
            }
        }

        let reads = std::rc::Rc::new(std::cell::Cell::new(0));
        let mut source = Stirred::new(Counting { reads: reads.clone() }, b"material".to_vec())
            .expect("material");
        let mut out = [0u8; 192];
        source.fill(&mut out).expect("a draw");
        assert_eq!(reads.get(), 3, "192 bytes should have taken three reads, not {}", reads.get());
    }
}
