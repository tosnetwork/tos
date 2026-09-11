//! Public system ciphertexts only; this module never mutates an account.
use crate::ffi::AbiStatus as Error;
use bulletproofs::PedersenGens;
use curve25519_dalek::{Scalar, RistrettoPoint, ristretto::CompressedRistretto, traits::IsIdentity};
use merlin::Transcript;

// Domain identity and Deposit admission limits are authenticated host obligations.
// A successful return authorizes neither issuance nor an account mutation.
pub(crate) fn encrypt_encoded(domain: &[u8; 80], id: &[u8; 32], recipient: &[u8; 32],
    amount: u64) -> Result<[[u8; 32]; 2], Error> {
    if amount == 0 { return Err(Error::UNO_CRYPTO_DECODE); }
    let p = CompressedRistretto(*recipient).decompress().ok_or(Error::UNO_CRYPTO_DECODE)?;
    if p.is_identity() { return Err(Error::UNO_CRYPTO_DECODE); }
    let mut transcript = Transcript::new(b"uno-v2/system-encryption");
    transcript.append_message(b"protocol-domain", domain);
    transcript.append_message(b"deposit-id", id);
    transcript.append_message(b"recipient-P", recipient);
    transcript.append_message(b"amount", &amount.to_le_bytes());
    let mut wide = [0; 64];
    transcript.challenge_bytes(b"r", &mut wide);
    finish(p, amount, &wide)
}

// The caller has decoded a nonidentity recipient and checked a positive u64 amount.
// Wide reduction has negligible statistical bias, not exact uniformity.
fn finish(p: RistrettoPoint, amount: u64, wide: &[u8; 64]) -> Result<[[u8; 32]; 2], Error> {
    let r = Scalar::from_bytes_mod_order_wide(wide);
    if r == Scalar::ZERO { return Err(Error::UNO_CRYPTO_DECODE); }
    let pc = PedersenGens::default();
    // These are scalar/group operations, not unchecked monetary arithmetic.
    let c = Scalar::from(amount) * pc.B + r * pc.B_blinding;
    // In the prime-order group, nonzero r and nonidentity p imply r*p != 0.
    let d = r * p;
    Ok([c.compress().to_bytes(), d.compress().to_bytes()])
}

#[cfg(test)]
mod tests {
    use super::*;
    use bulletproofs::PedersenGens;
    use curve25519_dalek::{Scalar, ristretto::CompressedRistretto};

    fn encrypt(domain: &[u8;80], id: &[u8;32], recipient: &[u8;32], amount: u64)
        -> Result<[[u8;32];2], Error> {
        encrypt_encoded(domain, id, recipient, amount)
    }

    fn domain() -> [u8;80] {
        let mut bytes = [0u8;80];
        bytes[..12].copy_from_slice(&[2,0,3,0,4,0,5,0,249,255,255,255]);
        bytes[12..44].fill(8);
        bytes[44..48].copy_from_slice(&[2,0,0,0]);
        bytes[48..80].fill(9);
        bytes
    }

    #[test]
    fn system_ciphertext_decrypts_to_the_public_amount() {
        let pc = PedersenGens::default();
        let secret = Scalar::from(11u64);
        let recipient = (secret.invert() * pc.B_blinding).compress().to_bytes();
        let encoded = encrypt(&domain(), &[10; 32], &recipient, 123)
            .expect("valid public system encryption must succeed");
        assert_eq!(hex(&encoded[0]), "5e24f609c9cd20bdee88a48bf0649613ff19d9dc6b8e57f690cf69d817dc5153");
        assert_eq!(hex(&encoded[1]), "34b2c6c8ec0f8028607358e6274d1165e6a79937a076567b2bcf0d67df7e6d01");
        let c = CompressedRistretto(encoded[0]).decompress().expect("canonical commitment");
        let d = CompressedRistretto(encoded[1]).decompress().expect("canonical handle");
        assert_eq!(c - secret * d, Scalar::from(123u64) * pc.B);
    }

    fn hex(bytes: &[u8]) -> String { bytes.iter().map(|b| format!("{b:02x}")).collect() }

    #[test]
    fn system_abi_checks_layout_failure_atomicity_and_both_components() {
        use crate::ffi::*;
        assert_eq!(std::mem::size_of::<SystemEncryptionRequest>(), 160);
        assert_eq!(std::mem::offset_of!(SystemEncryptionRequest, amount), 152);
        assert_eq!(std::mem::size_of::<SystemCiphertext>(), 64);
        let mut request = SystemEncryptionRequest { abi_version: UNO_CRYPTO_ABI_VERSION,
            domain: domain(), deposit_id: [10;32],
            recipient: PedersenGens::default().B_blinding.compress().to_bytes(), amount: 123 };
        let sentinel = SystemCiphertext { commitment: [55;32], handle: [66;32] };
        let mut output = sentinel;
        unsafe {
            assert_eq!(uno_crypto_system_encrypt_v1(&request, &mut output), 0);
            assert_ne!(output, sentinel);
            assert_eq!(uno_crypto_system_verify_v1(&request, &output), 0);
            let mut altered = output; altered.commitment[0] ^= 1;
            assert_eq!(uno_crypto_system_verify_v1(&request, &altered), 3);
            altered = output; altered.handle[0] ^= 1;
            assert_eq!(uno_crypto_system_verify_v1(&request, &altered), 3);
            output = sentinel;
            request.abi_version = 0;
            assert_eq!(uno_crypto_system_encrypt_v1(&request, &mut output), 1);
            assert_eq!(uno_crypto_system_verify_v1(&request, &output), 1);
            assert_eq!(output, sentinel);
            request.abi_version = UNO_CRYPTO_ABI_VERSION;
            request.amount = 0;
            assert_eq!(uno_crypto_system_encrypt_v1(&request, &mut output), 2);
            assert_eq!(output, sentinel);
            request.amount = 123;
            INJECT_UNWIND.with(|flag| flag.set(true));
            assert_eq!(uno_crypto_system_encrypt_v1(&request, &mut output), 5);
            assert_eq!(output, sentinel);
            INJECT_UNWIND.with(|flag| flag.set(true));
            assert_eq!(uno_crypto_system_verify_v1(&request, &output), 5);
            assert_eq!(uno_crypto_system_encrypt_v1(std::ptr::null(), &mut output), 1);
            assert_eq!(uno_crypto_system_encrypt_v1(&request, std::ptr::null_mut()), 1);
            assert_eq!(uno_crypto_system_verify_v1(&request, std::ptr::null()), 1);
            assert_eq!(uno_crypto_system_verify_v1(std::ptr::null(), &output), 1);
        }
    }

    #[test]
    fn system_verify_checks_request_version_independently() {
        use crate::ffi::*;
        let request = SystemEncryptionRequest { abi_version: 0,
            domain: domain(), deposit_id: [10;32],
            recipient: PedersenGens::default().B_blinding.compress().to_bytes(), amount: 123 };
        let supplied = SystemCiphertext { commitment: [0;32], handle: [0;32] };
        unsafe {
            assert_eq!(uno_crypto_system_verify_v1(&request, &supplied), 1);
            assert_eq!(uno_crypto_system_verify_v1(std::ptr::null(), &supplied), 1);
        }
    }

    #[test]
    fn system_encryption_rejects_each_invalid_input() {
        let p = PedersenGens::default().B_blinding;
        let key = p.compress().to_bytes();
        assert_eq!(encrypt(&domain(), &[10;32], &key, 0), Err(Error::UNO_CRYPTO_DECODE));
        assert!(encrypt(&domain(), &[10;32], &key, u64::MAX).is_ok());
        assert_eq!(encrypt(&domain(), &[10;32], &[0;32], 1), Err(Error::UNO_CRYPTO_DECODE));
        assert_eq!(encrypt(&domain(), &[10;32], &[255;32], 1), Err(Error::UNO_CRYPTO_DECODE));
        assert_eq!(finish(p, 1, &[0;64]), Err(Error::UNO_CRYPTO_DECODE));
    }

    #[test]
    fn system_encryption_binds_every_public_field() {
        let pc = PedersenGens::default();
        let key = pc.B_blinding.compress().to_bytes();
        let baseline = encrypt(&domain(), &[10;32], &key, 123).expect("baseline");
        for field in 0..80 {
            let mut changed = domain();
            changed[field] ^= 1;
            assert_ne!(encrypt(&changed, &[10;32], &key, 123).expect("changed domain"), baseline,
                "domain byte {field} must affect the ciphertext");
        }
        assert_ne!(encrypt(&domain(), &[11;32], &key, 123).expect("changed id"), baseline);
        let other = (Scalar::from(2u64) * pc.B_blinding).compress().to_bytes();
        let changed_key = encrypt(&domain(), &[10;32], &other, 123).expect("changed key");
        // C only changes with P if P was absorbed, not merely used in D=rP.
        assert_ne!(changed_key[0], baseline[0]);
        let changed_amount = encrypt(&domain(), &[10;32], &key, 124).expect("changed amount");
        // D only changes with amount if amount was absorbed, not just added to C.
        assert_ne!(changed_amount[1], baseline[1]);
    }
    #[test]
    fn system_verify_rejects_ciphertext_from_another_transcript_domain() {
        use crate::ffi::*;
        let p = PedersenGens::default().B_blinding;
        let recipient = p.compress().to_bytes();
        let request = SystemEncryptionRequest { abi_version: UNO_CRYPTO_ABI_VERSION,
            domain: domain(), deposit_id: [10; 32], recipient, amount: 123 };
        let mut other = Transcript::new(b"uno-v2/system-encryption-wrong-domain");
        other.append_message(b"protocol-domain", &request.domain);
        other.append_message(b"deposit-id", &request.deposit_id);
        other.append_message(b"recipient-P", &request.recipient);
        other.append_message(b"amount", &request.amount.to_le_bytes());
        let mut wide = [0; 64];
        other.challenge_bytes(b"r", &mut wide);
        let [commitment, handle] = finish(p, request.amount, &wide).expect("nonzero test challenge");
        let supplied = SystemCiphertext { commitment, handle };
        // Valid encodings reach the actual reconstruction/comparison ABI.
        assert_eq!(unsafe { uno_crypto_system_verify_v1(&request, &supplied) }, 3);
    }

}
