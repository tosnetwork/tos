/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! The one value in a phase-2 contribution that must never be written down.
//!
//! A participant multiplies `delta` by a scalar they draw. Their contribution
//! is sound exactly as long as that scalar is destroyed: anyone who learns
//! every participant's scalar can forge proofs for the circuit, and anyone who
//! learns *one* participant's scalar has learned nothing, because the rest
//! still multiply. So the discipline is per-participant and it is absolute --
//! a secret that is echoed, logged, sent anywhere or left in a file has simply
//! not been destroyed, whatever else the ceremony did right.
//!
//! This type exists to make the careless version of that not compile:
//!
//! * there is no constructor from bytes, from a string, or from a seed. A
//!   [`Secret`] can only come from an [`Entropy`] source;
//! * it is not `Clone` and not `Copy`, so the compiler tracks the one copy;
//! * it is not `Serialize` and not `Display`, and its `Debug` prints a
//!   placeholder. Putting one into a log line, a JSON artifact or a panic
//!   message is either a compile error or prints nothing;
//! * it wipes itself when it is dropped, including the intermediate bytes it
//!   was reduced from.
//!
//! None of that protects against an attacker who can read the process's
//! memory, and it is not meant to. It protects against the way these secrets
//! are actually lost, which is a developer adding a print statement to see
//! what is going on.
//!
//! # Where the scalar comes from
//!
//! Sixty-four bytes, reduced modulo the group order. Not thirty-two: the
//! order is a shade under 2^255, so reducing a 256-bit string biases the
//! result towards the low end by a fraction near 2^-128 -- small, but it is a
//! bias in a secret, and it costs nothing to remove. Reducing 512 bits leaves
//! a bias below 2^-256, which is past the point where anything else is the
//! weakest part.

use ark_bls12_381::Fr;
use ark_ff::{Field, PrimeField, Zero};
use zeroize::Zeroize;

use crate::entropy::Entropy;
use crate::error::{Error, Result};

/// A contribution secret: known to one participant, for as long as it takes to
/// use it, and then to nobody.
pub struct Secret {
    value: Fr,
}

impl Secret {
    /// Draws a fresh secret.
    ///
    /// The only way to make one. Fails rather than returning a weak scalar:
    ///
    /// * zero would send `delta` to the identity and destroy the key outright,
    ///   and it has no inverse, so the queries could not be divided;
    /// * one would leave the key untouched -- not a hole for anybody else, but
    ///   this participant would have contributed nothing while appearing to
    ///   contribute, which is worse than failing.
    ///
    /// A sound generator produces either with probability near 2^-254, so
    /// seeing one of these errors means the generator is broken, not that the
    /// draw was unlucky. That is the whole reason to check.
    pub fn draw(entropy: &mut dyn Entropy) -> Result<Self> {
        // `Zeroizing` rather than a call at the end: every `?` below is an
        // early return, and an explicit wipe placed after them is skipped by
        // exactly the paths that took one. A buffer wiped only on success is
        // wiped only when nothing went wrong.
        let mut wide = zeroize::Zeroizing::new([0u8; 64]);
        entropy.fill(wide.as_mut())?;
        let value = Fr::from_le_bytes_mod_order(wide.as_ref());
        drop(wide);

        if value.is_zero() {
            return Err(Error::Entropy(
                "the drawn secret is zero; the generator is broken, because a sound one reaches \
                 this about once in 2^254 draws"
                    .into(),
            ));
        }
        if value == Fr::ONE {
            return Err(Error::Entropy(
                "the drawn secret is one, which would leave the key unchanged; the generator is \
                 broken"
                    .into(),
            ));
        }
        Ok(Self { value })
    }

    /// The scalar, for this crate's arithmetic only.
    ///
    /// Crate-private on purpose: a caller outside cannot reach the value, so
    /// it cannot be printed or stored by anything but the contribution code
    /// that has to multiply by it.
    pub(crate) fn value(&self) -> &Fr {
        &self.value
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        self.value.zeroize();
    }
}

/// Prints a placeholder. Deliberately not the value, and deliberately present
/// -- without it, a struct holding a `Secret` could not derive `Debug` at all,
/// and the tempting fix is to expose the scalar.
impl std::fmt::Debug for Secret {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Secret(<withheld>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entropy::OperatingSystem;
    use ark_ff::BigInteger;

    /// A source under the test's control, so the checks below are about the
    /// reduction rather than about the system generator.
    struct Given(Vec<u8>);

    impl Entropy for Given {
        fn fill(&mut self, out: &mut [u8]) -> Result<()> {
            if self.0.len() < out.len() {
                return Err(Error::Entropy("not enough material".into()));
            }
            out.copy_from_slice(&self.0[..out.len()]);
            Ok(())
        }
    }

    #[test]
    fn a_drawn_secret_is_usable_and_invertible() {
        let secret = Secret::draw(&mut OperatingSystem).expect("a secret");
        let inverse = secret.value().inverse().expect("an inverse");
        assert_eq!(*secret.value() * inverse, Fr::ONE);
    }

    #[test]
    fn two_draws_differ() {
        let first = Secret::draw(&mut OperatingSystem).expect("a secret");
        let second = Secret::draw(&mut OperatingSystem).expect("a secret");
        assert_ne!(first.value(), second.value(), "two draws came back equal");
    }

    #[test]
    fn a_zero_draw_is_refused() {
        // A source stuck at zero is caught by the entropy layer first; this
        // reaches the scalar check by handing over the group order itself,
        // which is a perfectly varied byte string that reduces to zero.
        let mut order = Fr::MODULUS.to_bytes_le();
        order.resize(64, 0);
        let error = Secret::draw(&mut Given(order)).expect_err("zero was accepted");
        assert!(format!("{error}").contains("zero"), "{error}");
    }

    #[test]
    fn a_draw_of_one_is_refused() {
        let mut one = vec![0u8; 64];
        one[0] = 1;
        // The all-but-one-byte-zero string is not a constant block, so it
        // reaches the scalar check.
        let error = Secret::draw(&mut Given(one)).expect_err("one was accepted");
        assert!(format!("{error}").contains("one"), "{error}");
    }

    /// The reduction is over the full sixty-four bytes, not the first
    /// thirty-two. Two strings that agree on their low half and differ above
    /// it must give different secrets; if only the low half were read they
    /// would give the same one.
    #[test]
    fn the_whole_draw_is_used() {
        let mut low = vec![0xa5u8; 64];
        low[32..].fill(0);
        let mut high = vec![0xa5u8; 64];
        high[32..].fill(0);
        high[40] = 0x01;

        let first = Secret::draw(&mut Given(low)).expect("a secret");
        let second = Secret::draw(&mut Given(high)).expect("a secret");
        assert_ne!(first.value(), second.value(), "the top half of the draw was discarded");
    }

    /// The property this type exists for: it does not print itself.
    #[test]
    fn the_value_is_not_in_the_debug_output() {
        let secret = Secret::draw(&mut OperatingSystem).expect("a secret");
        let printed = format!("{secret:?}");
        assert_eq!(printed, "Secret(<withheld>)");
        // And not merely elided -- no digit of the scalar appears.
        let value = format!("{}", secret.value().into_bigint());
        assert!(!printed.contains(&value), "the debug output carries the scalar");
    }
}
