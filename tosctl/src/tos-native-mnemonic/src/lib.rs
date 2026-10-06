/*
 * Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */

//! TOS mnemonic derivation shared by `tosctl` wallet commands.
//!
//! This intentionally follows the existing TOS SDK algorithm. It uses the
//! BIP-39 English word list, but it is not a BIP-39 checksum mnemonic or a
//! BIP-39 seed derivation.

use anyhow::Context;
use bip39::Language;
use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2_hmac;
use rand::{Rng, rngs::OsRng};
use sha2::Sha512;
use zeroize::{Zeroize, Zeroizing};

const PBKDF_ITERATIONS: u32 = 100_000;
const BASIC_SEED_ITERATIONS: u32 = PBKDF_ITERATIONS / 256;

type HmacSha512 = Hmac<Sha512>;

fn normalize(words: &str) -> Vec<String> {
    words.split_whitespace().map(|word| word.to_ascii_lowercase()).collect()
}

fn entropy(words: &[String], password: &str) -> anyhow::Result<[u8; 64]> {
    let phrase = Zeroizing::new(words.join(" "));
    let mut mac =
        HmacSha512::new_from_slice(phrase.as_bytes()).context("initialize TOS mnemonic HMAC")?;
    mac.update(password.as_bytes());
    Ok(mac.finalize().into_bytes().into())
}

fn is_basic_seed(words: &[String], password: &str) -> anyhow::Result<bool> {
    let mut source = entropy(words, password)?;
    let mut check = [0u8; 64];
    pbkdf2_hmac::<Sha512>(&source, b"TOS seed version", BASIC_SEED_ITERATIONS, &mut check);
    source.zeroize();
    let valid = check[0] == 0;
    check.zeroize();
    Ok(valid)
}

pub fn validate(phrase: &str, password: &str) -> anyhow::Result<Vec<String>> {
    let mut words = Zeroizing::new(normalize(phrase));
    if !matches!(words.len(), 12 | 24) {
        anyhow::bail!("TOS mnemonics must contain exactly 12 or 24 words");
    }
    let wordlist = Language::English.word_list();
    // Report the position only: a misspelled word is close to the real one,
    // so echoing it would disclose part of the secret.
    if let Some(position) =
        words.iter().position(|word| wordlist.binary_search(&word.as_str()).is_err())
    {
        anyhow::bail!("Unknown mnemonic word at position {}", position.saturating_add(1));
    }
    if !is_basic_seed(&words, password)? {
        anyhow::bail!("Mnemonic does not satisfy the TOS basic-seed check");
    }
    Ok(std::mem::take(&mut *words))
}

pub fn generate(word_count: usize) -> anyhow::Result<Vec<String>> {
    if !matches!(word_count, 12 | 24) {
        anyhow::bail!("--words must be 12 or 24");
    }
    let wordlist = Language::English.word_list();
    loop {
        let mut words = Zeroizing::new(
            (0..word_count)
                .map(|_| wordlist[OsRng.gen_range(0..wordlist.len())].to_owned())
                .collect::<Vec<_>>(),
        );
        if is_basic_seed(&words, "")? {
            return Ok(std::mem::take(&mut *words));
        }
    }
}

pub fn private_seed(phrase: &str, password: &str) -> anyhow::Result<[u8; 32]> {
    let words = Zeroizing::new(validate(phrase, password)?);
    let mut source = entropy(&words, password)?;
    let mut derived = [0u8; 64];
    pbkdf2_hmac::<Sha512>(&source, b"TOS default seed", PBKDF_ITERATIONS, &mut derived);
    source.zeroize();
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&derived[..32]);
    derived.zeroize();
    Ok(seed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_bip39_words_that_do_not_form_a_tos_basic_seed() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        assert!(validate(phrase, "").is_err());
    }

    #[test]
    fn generated_mnemonic_round_trips() {
        let words = generate(12).unwrap();
        let phrase = Zeroizing::new(words.join(" "));
        assert_eq!(validate(&phrase, "").unwrap(), words);
        assert_ne!(private_seed(&phrase, "").unwrap(), [0u8; 32]);
    }
}

#[cfg(test)]
mod frozen_tests {
    use super::*;
    #[test]
    fn preserves_native_vectors_and_exact_passwords() {
        let fixtures: serde_json::Value =
            serde_json::from_str(include_str!("../tests/fixtures/native-pq.json")).unwrap();
        for vector in fixtures["vectors"].as_array().unwrap() {
            let phrase = vector["phrase"].as_str().unwrap();
            let password = vector["password"].as_str().unwrap();
            let expected = hex::decode(vector["master_hex"].as_str().unwrap()).unwrap();
            assert_eq!(
                private_seed(phrase, password).expect("native frozen mnemonic rejected").as_slice(),
                expected,
                "native seed mapping changed"
            );
            let normalized = format!("  {}\n", phrase.to_uppercase().replace(' ', "\t"));
            assert_eq!(
                private_seed(&normalized, password)
                    .expect("native normalization rejected")
                    .as_slice(),
                expected,
                "native normalization changed"
            );
            let wrong_password = format!("{password}wrong");
            if let Ok(seed) = private_seed(phrase, &wrong_password) {
                assert_ne!(seed.as_slice(), expected, "password ignored");
            }
        }
        assert!(validate("secret-invalid", "").is_err());
    }
}
