#[cfg(panic = "abort")]
compile_error!("uno-crypto requires panic=unwind for ABI containment");

use orchard::Bundle;
pub mod context;
pub mod decode;
pub mod ffi;
pub mod tree;
pub mod tree_ffi;
pub mod transfer_transcript;
#[cfg(test)]
mod vk_snapshot;
use orchard::{
    bundle::{Authorized, BundleVersion, Flags},
    circuit::{OrchardCircuitVersion, VerifyingKey},
    tree::Anchor,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnsupportedProfile;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyConstructionFailed;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationError {
    Profile,
    Shape(ProofShapeError),
    NonCanonicalAnchor,
    Context(context::ContextError),
    Proof,
    SpendSignature,
    BindingSignature,
}

// The key cannot be supplied or replaced by a bundle or FFI caller.
// This verifies cryptography, not the caller's transaction authorization policy.
pub struct FixedVerifier {
    key: VerifyingKey,
}

impl FixedVerifier {
    // Matching public amounts is not authorization to mint or settle a receipt.
    pub fn verify_in_context(
        &self,
        bundle: &Bundle<Authorized, i64>,
        context: context::PublicContext,
        sighash: &[u8; 32],
        max_actions: usize,
        max_proof_bytes: usize,
    ) -> Result<(), VerificationError> {
        context::check_context(context, *bundle.value_balance(), bundle.flags())
            .map_err(VerificationError::Context)?;
        self.verify_bundle(bundle, sighash, max_actions, max_proof_bytes)
    }

    pub fn new() -> Result<Self, KeyConstructionFailed> {
        let key =
            std::panic::catch_unwind(|| VerifyingKey::build(OrchardCircuitVersion::FixedPostNu6_2))
                .map_err(|_| KeyConstructionFailed)?;
        Ok(Self { key })
    }

    pub fn check_bundle_profile(&self, bundle: BundleVersion) -> Result<(), UnsupportedProfile> {
        validate_profile(bundle, self.key.circuit_version())
    }

    pub fn verify_bundle(
        &self,
        bundle: &Bundle<Authorized, i64>,
        sighash: &[u8; 32],
        max_actions: usize,
        max_proof_bytes: usize,
    ) -> Result<(), VerificationError> {
        self.check_bundle_profile(bundle.bundle_version())
            .map_err(|_| VerificationError::Profile)?;
        validate_proof_shape(
            bundle.actions().len(),
            bundle.authorization().proof().as_ref().len(),
            max_actions,
            max_proof_bytes,
        )
        .map_err(VerificationError::Shape)?;
        if !has_canonical_output_only_anchor(bundle.flags(), bundle.anchor()) {
            return Err(VerificationError::NonCanonicalAnchor);
        }
        bundle.verify_proof(&self.key).map_err(|_| VerificationError::Proof)?;
        for action in bundle.actions() {
            action
                .rk()
                .verify(sighash, action.authorization())
                .map_err(|_| VerificationError::SpendSignature)?;
        }
        bundle
            .binding_validating_key()
            .verify(sighash, bundle.authorization().binding_signature())
            .map_err(|_| VerificationError::BindingSignature)?;
        Ok(())
    }
}

// The flag is public; real versus dummy note values are not available here.
fn has_canonical_output_only_anchor(flags: &Flags, anchor: &Anchor) -> bool {
    flags.spends_enabled() || *anchor == Anchor::empty_tree()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofShapeError {
    EmptyOrUnconfigured,
    ActionLimit,
    LengthOverflow,
    ByteLimit,
    NonCanonicalLength,
}

// These limits must come from authenticated configuration before host use.
// No allocation or cryptographic verification is performed here.
pub fn validate_proof_shape(
    actions: usize,
    proof_bytes: usize,
    max_actions: usize,
    max_proof_bytes: usize,
) -> Result<(), ProofShapeError> {
    if actions == 0 || max_actions == 0 || max_proof_bytes == 0 {
        return Err(ProofShapeError::EmptyOrUnconfigured);
    }
    if actions > max_actions {
        return Err(ProofShapeError::ActionLimit);
    }
    let expected = actions
        .checked_mul(2272)
        .and_then(|bytes| bytes.checked_add(2720))
        .ok_or(ProofShapeError::LengthOverflow)?;
    if expected > max_proof_bytes {
        return Err(ProofShapeError::ByteLimit);
    }
    if proof_bytes != expected {
        return Err(ProofShapeError::NonCanonicalLength);
    }
    Ok(())
}

// Prototype gate only; this does not validate a proof or authorize a bundle.
pub fn validate_profile(
    bundle: BundleVersion,
    circuit: OrchardCircuitVersion,
) -> Result<(), UnsupportedProfile> {
    if bundle != BundleVersion::orchard_v2() || circuit != OrchardCircuitVersion::FixedPostNu6_2 {
        return Err(UnsupportedProfile);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn measure_proofs(
        label: &str,
        samples: usize,
        verifier: &FixedVerifier,
        mut prove: impl FnMut() -> (Bundle<Authorized, i64>, std::time::Duration),
    ) {
        if samples == 0 {
            return;
        }
        let mut elapsed = Vec::with_capacity(samples);
        let mut previous_proof = Vec::new();
        for sample in 0..samples {
            let (bundle, duration) = prove();
            assert_eq!(verifier.verify_bundle(&bundle, &[42; 32], 2, 7264), Ok(()));
            let proof = bundle.authorization().proof().as_ref();
            assert!(proof != previous_proof.as_slice(), "measurement reused a cached proof");
            previous_proof = proof.to_vec();
            let ms = duration.as_secs_f64() * 1000.0;
            println!("PROVE_SAMPLE workload={label} sample={sample} actions=2 proof_bytes=7264 ms={ms}");
            elapsed.push(ms);
        }
        elapsed.sort_by(f64::total_cmp);
        let rank = |percent: usize| elapsed[(samples * percent).div_ceil(100) - 1];
        println!("PROVE_SUMMARY workload={label} samples={samples} unit=ms p50={} max={}",
                 rank(50), elapsed[samples - 1]);
        // Small pilot runs do not support useful tail percentile estimates.
        if samples >= 100 {
            println!("PROVE_TAIL workload={label} p95={} p99={}", rank(95), rank(99));
        }
    }

    fn encoded_actions(bundle: &Bundle<Authorized, i64>) -> Vec<decode::EncodedAction> {
        use crate::decode::EncodedAction;
        bundle
            .actions()
            .iter()
            .map(|action| EncodedAction {
                cv_net: action.cv_net().to_bytes(),
                nullifier: action.nullifier().to_bytes(),
                rk: action.rk().into(),
                cmx: action.cmx().to_bytes(),
                epk: action.encrypted_note().epk_bytes,
                enc_ciphertext: action.encrypted_note().enc_ciphertext,
                out_ciphertext: action.encrypted_note().out_ciphertext,
                spend_signature: action.authorization().into(),
            })
            .collect()
    }

    fn ffi_status(
        bundle: &Bundle<Authorized, i64>,
        mutate: impl FnOnce(&mut ffi::VerifyRequest),
    ) -> u32 {
        let actions = encoded_actions(bundle);
        let balance = *bundle.value_balance();
        let (context, principal, fee) = if balance < 0 {
            (
                2,
                u64::try_from(balance.checked_neg().expect("fixture magnitude"))
                    .expect("principal"),
                0,
            )
        } else {
            (0, 0, u64::try_from(balance).expect("fee"))
        };
        let mut request = ffi::VerifyRequest {
            abi_version: 0,
            profile: 1,
            context,
            flags: bundle.flag_byte(),
            value_balance: balance,
            principal_hi: 0,
            principal_lo: principal,
            fee_hi: 0,
            fee_lo: fee,
            anchor: bundle.anchor().to_bytes(),
            sighash: [42; 32],
            binding_signature: bundle.authorization().binding_signature().into(),
            actions: actions.as_ptr(),
            action_count: actions.len(),
            proof: bundle.authorization().proof().as_ref().as_ptr(),
            proof_bytes: bundle.authorization().proof().as_ref().len(),
            max_actions: 2,
            max_proof_bytes: 7264,
        };
        mutate(&mut request);
        unsafe { ffi::uno_crypto_verify_v0(&request) }
    }

    fn export_abi_fixture(bundle: &Bundle<Authorized, i64>, name: &str) {
        use std::io::Write;
        let Some(directory) = std::env::var_os("UNO_ABI_FIXTURE_DIR") else {
            return;
        };
        assert_eq!(bundle.actions().len(), 2);
        assert_eq!(bundle.authorization().proof().as_ref().len(), 7264);
        let mut bytes = b"UNOABIT0".to_vec();
        bytes.push(bundle.flag_byte());
        bytes.extend_from_slice(&bundle.value_balance().to_le_bytes());
        bytes.extend_from_slice(&bundle.anchor().to_bytes());
        bytes.extend_from_slice(&<[u8; 64]>::from(bundle.authorization().binding_signature()));
        bytes.extend_from_slice(bundle.authorization().proof().as_ref());
        for action in encoded_actions(bundle) {
            for field in [&action.cv_net, &action.nullifier, &action.rk, &action.cmx, &action.epk] {
                bytes.extend_from_slice(field);
            }
            bytes.extend_from_slice(&action.enc_ciphertext);
            bytes.extend_from_slice(&action.out_ciphertext);
            bytes.extend_from_slice(&action.spend_signature);
        }
        let path = std::path::PathBuf::from(directory).join(name);
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .expect("create a new public test fixture; never overwrite");
        file.write_all(&bytes).expect("write public fixture");
    }

    fn measurement_seed(actions: u8, sample: u8) -> [u8; 32] {
        let mut seed = [actions; 32];
        seed[31] ^= sample;
        seed
    }

    #[test]
    fn measurement_seed_has_independent_sample_identity() {
        let seed = measurement_seed(4, 7);
        assert_eq!(&seed[..31], &[4; 31]);
        assert_eq!(seed[31], 3, "sample identity must change the generator seed");
        assert_eq!(measurement_seed(4, 0), [4; 32], "sample zero preserves archived fixtures");
    }

    // Manual measurement producer, not a production wire or an activation gate.
    // All keys, randomness and resulting notes are public test material.
    #[test]
    #[ignore = "manual multi-shape measurement; requires UNO_SHAPE_FIXTURE_DIR"]
    fn export_measurement_shapes() {
        use std::io::Write;
        use incrementalmerkletree::Hashable;
        use orchard::{
            builder::{Builder, BundleType},
            circuit::ProvingKey,
            keys::{FullViewingKey, Scope, SpendAuthorizingKey, SpendingKey},
            tree::{MerkleHashOrchard, MerklePath},
            value::NoteValue,
        };
        use rand::SeedableRng;

        let directory = std::env::var_os("UNO_SHAPE_FIXTURE_DIR")
            .expect("UNO_SHAPE_FIXTURE_DIR is required; missing output is not a successful measurement");
        let sample = match std::env::var("UNO_SHAPE_SAMPLE") {
            Ok(value) => value.parse::<u8>().expect("UNO_SHAPE_SAMPLE must be an integer in [0,255]"),
            Err(std::env::VarError::NotPresent) => 0,
            Err(error) => panic!("invalid UNO_SHAPE_SAMPLE: {error}"),
        };
        let pk = ProvingKey::build(OrchardCircuitVersion::FixedPostNu6_2);
        let sk = SpendingKey::from_bytes([0; 32]).expect("public test spending key");
        let recipient = FullViewingKey::from(&sk).address_at(0u32, Scope::External);
        for count in [2usize, 4, 8] {
            let seed = measurement_seed(u8::try_from(count).expect("shape seed"), sample);
            let mut rng = rand::rngs::StdRng::from_seed(seed);
            let count_u64 = u64::try_from(count).expect("shape count");
            let per_output = 5000u64.checked_div(count_u64).expect("nonzero shape count");
            assert_eq!(per_output.checked_mul(count_u64), Some(5000));
            let mut builder = Builder::new(
                BundleType::DEFAULT,
                BundleVersion::orchard_v2(),
                Flags::SPENDS_DISABLED,
                Anchor::empty_tree(),
            ).expect("shape builder");
            for _ in 0..count {
                builder.add_output(None, recipient, NoteValue::from_raw(per_output), [0; 512])
                    .expect("shape output");
            }
            let (unsigned, metadata) = builder.build::<i64>(&mut rng).expect("shape build").expect("nonempty shape");
            let begin = std::time::Instant::now();
            let proven = unsigned.create_proof(&pk, &mut rng).expect("shape proof");
            let prove_ns = begin.elapsed().as_nanos();
            let bundle = proven.apply_signatures(&mut rng, [42; 32], &[]).expect("shape signatures");
            assert_eq!(bundle.actions().len(), count, "builder must produce the requested shape");
            assert_eq!(*bundle.value_balance(), -5000, "shape must preserve total principal");
            let proof_bytes = count.checked_mul(2272).and_then(|n| n.checked_add(2720))
                .expect("shape proof length");
            assert_eq!(bundle.authorization().proof().as_ref().len(), proof_bytes);
            let set_limits = |request: &mut ffi::VerifyRequest| {
                request.max_actions = count;
                request.max_proof_bytes = proof_bytes;
            };
            assert_eq!(ffi_status(&bundle, set_limits), 0, "real ABI must accept generated shape");
            assert_eq!(ffi_status(&bundle, |request| {
                set_limits(request);
                request.sighash[0] ^= 1;
            }), 3, "real ABI must reject a differently authorized shape");

            // T1 is a private measurement-file revision with explicit u64 LE
            // lengths. T0 fixtures and the production ABI remain unchanged.
            let export = |bundle: &Bundle<Authorized, i64>, kind: &str, prove_ns: u128| {
            let mut bytes = b"UNOABIT1".to_vec();
            bytes.extend_from_slice(&count_u64.to_le_bytes());
            bytes.extend_from_slice(&u64::try_from(proof_bytes).expect("proof length encoding").to_le_bytes());
            bytes.push(bundle.flag_byte());
            bytes.extend_from_slice(&bundle.value_balance().to_le_bytes());
            bytes.extend_from_slice(&bundle.anchor().to_bytes());
            bytes.extend_from_slice(&<[u8; 64]>::from(bundle.authorization().binding_signature()));
            bytes.extend_from_slice(bundle.authorization().proof().as_ref());
            for action in encoded_actions(&bundle) {
                for field in [&action.cv_net, &action.nullifier, &action.rk, &action.cmx, &action.epk] {
                    bytes.extend_from_slice(field);
                }
                bytes.extend_from_slice(&action.enc_ciphertext);
                bytes.extend_from_slice(&action.out_ciphertext);
                bytes.extend_from_slice(&action.spend_signature);
            }
            let path = std::path::PathBuf::from(&directory).join(format!("{kind}-{count}.bin"));
            let mut file = std::fs::OpenOptions::new().write(true).create_new(true)
                .open(&path).expect("create fresh shape fixture; never overwrite");
            file.write_all(&bytes).expect("write shape fixture");
            file.flush().expect("flush shape fixture");
            println!("SHAPE_FIXTURE kind={kind} actions={count} proof_bytes={proof_bytes} prove_ns={prove_ns} sample={sample} seed_first={} seed_last={} path={}",
                     seed[0], seed[31], path.display());
            };
            export(&bundle, "funding", prove_ns);

            // Every requested spend consumes a distinct real funding output.
            // Build authentication paths from the actual randomized Action order.
            let mut layers = vec![bundle.actions().iter()
                .map(|action| MerkleHashOrchard::from_cmx(action.cmx())).collect::<Vec<_>>()];
            let mut level = 0u8;
            while layers.last().expect("leaf layer").len() > 1 {
                let nodes = layers.last().expect("tree layer");
                assert_eq!(nodes.len().checked_rem(2), Some(0), "power-of-two fixture layer");
                let parents = nodes.chunks_exact(2)
                    .map(|pair| MerkleHashOrchard::combine(level.into(), &pair[0], &pair[1])).collect();
                layers.push(parents);
                level = level.checked_add(1).expect("fixture tree level");
            }
            let commitments: Vec<_> = bundle.actions().iter().map(|action| action.cmx().to_bytes()).collect();
            let note_tree = tree::NoteTree::default().append_batch(&commitments, 0).expect("funding tree");
            let anchor = Option::<Anchor>::from(Anchor::from_bytes(note_tree.root())).expect("funding anchor");
            let fvk = FullViewingKey::from(&sk);
            let mut spender = Builder::new(BundleType::DEFAULT, BundleVersion::orchard_v2(),
                BundleVersion::orchard_v2().default_flags(), anchor).expect("multi-spend builder");
            let mut positions = std::collections::BTreeSet::new();
            for output in 0..count {
                let position = metadata.output_action_index(output).expect("funding output position");
                assert!(positions.insert(position), "each spend must consume a different output");
                let (note, _, _) = bundle.decrypt_output_with_key(position, &fvk.to_ivk(Scope::External))
                    .expect("recover real funding output");
                assert_eq!(note.value(), NoteValue::from_raw(per_output));
                let path = MerklePath::from_parts(u32::try_from(position).expect("position"),
                    std::array::from_fn(|depth| {
                        let sibling = (position >> depth) ^ 1;
                        layers.get(depth).and_then(|nodes| nodes.get(sibling)).copied()
                            .unwrap_or_else(|| MerkleHashOrchard::empty_root(u8::try_from(depth).expect("depth").into()))
                    }));
                assert_eq!(path.root(note.commitment().into()), anchor, "path must reach the funding tree");
                spender.add_spend(fvk.clone(), note, path).expect("distinct real spend");
            }
            let change = 5000u64.checked_sub(100).expect("principal covers fee");
            spender.add_output(None, recipient, NoteValue::from_raw(change), [0;512]).expect("change output");
            let (unsigned_spend, spend_metadata) = spender.build::<i64>(&mut rng)
                .expect("multi-spend build").expect("nonempty spend");
            assert_eq!(unsigned_spend.actions().len(), count);
            for spend in 0..count {
                assert!(spend_metadata.spend_action_index(spend).is_some(), "no requested spend may disappear");
            }
            let begin = std::time::Instant::now();
            let proven = unsigned_spend.create_proof(&pk, &mut rng).expect("multi-spend proof");
            let prove_ns = begin.elapsed().as_nanos();
            let spent = proven.apply_signatures(&mut rng, [42;32], &[SpendAuthorizingKey::from(&sk)])
                .expect("multi-spend signatures");
            assert_eq!(*spent.value_balance(), 100, "spent principal minus change equals fee");
            assert_eq!(spent.authorization().proof().as_ref().len(), proof_bytes);
            assert_eq!(ffi_status(&spent, set_limits), 0, "real ABI accepts multi-spend shape");
            assert_eq!(ffi_status(&spent, |request| {
                set_limits(request);
                request.sighash[0] ^= 1;
            }), 3, "real ABI rejects differently authorized multi-spend shape");
            export(&spent, "spend", prove_ns);
        }
    }

    fn decode_real_bundle(bundle: &Bundle<Authorized, i64>) -> Bundle<Authorized, i64> {
        use crate::decode::{decode_bundle, EncodedBundle};
        let actions = encoded_actions(bundle);
        decode_bundle(
            &EncodedBundle {
                profile: bundle.bundle_version(),
                flags: bundle.flag_byte(),
                value_balance: *bundle.value_balance(),
                anchor: bundle.anchor().to_bytes(),
                actions: &actions,
                proof: bundle.authorization().proof().as_ref(),
                binding_signature: bundle.authorization().binding_signature().into(),
            },
            2,
            7264,
        )
        .expect("decode real bundle")
    }

    #[test]
    fn real_bundle_requires_proof_and_signatures() {
        let proving_samples = match std::env::var("UNO_PROVING_SAMPLES") {
            Err(std::env::VarError::NotPresent) => 0,
            Err(error) => panic!("invalid measurement setting: {error}"),
            Ok(text) => {
                let count: usize = text.parse().expect("numeric proving sample count");
                assert!((3..=1000).contains(&count), "proving sample count must be in [3,1000]");
                count
            }
        };
        use incrementalmerkletree::Hashable;
        use orchard::{
            builder::{Builder, BundleType},
            bundle::Flags,
            circuit::ProvingKey,
            keys::{FullViewingKey, Scope, SpendAuthorizingKey, SpendingKey},
            tree::{Anchor, MerkleHashOrchard, MerklePath},
            value::NoteValue,
            Proof,
        };
        let mut rng = rand::rngs::OsRng;
        let sk = SpendingKey::from_bytes([0; 32]).expect("test spending key");
        let recipient = FullViewingKey::from(&sk).address_at(0u32, Scope::External);
        let mut builder = Builder::new(
            BundleType::DEFAULT,
            BundleVersion::orchard_v2(),
            Flags::SPENDS_DISABLED,
            Anchor::empty_tree(),
        )
        .expect("test builder");
        builder
            .add_output(None, recipient, NoteValue::from_raw(5000), [0; 512])
            .expect("test output");
        let (unsigned, metadata) =
            builder.build::<i64>(&mut rng).expect("build").expect("nonempty");
        let key_start = std::time::Instant::now();
        let pk = ProvingKey::build(OrchardCircuitVersion::FixedPostNu6_2);
        if proving_samples != 0 {
            println!("PROVING_KEY unit=ms elapsed={}", key_start.elapsed().as_secs_f64() * 1000.0);
        }
        let digest = [42; 32];
        let bundle = unsigned
            .clone()
            .create_proof(&pk, &mut rng)
            .expect("proof")
            .apply_signatures(&mut rng, digest, &[])
            .expect("signatures");
        let verifier = FixedVerifier::new().expect("fixed key");
        measure_proofs("output-only", proving_samples, &verifier, || {
            let unproven = unsigned.clone();
            let start = std::time::Instant::now();
            let proven = unproven.create_proof(&pk, &mut rng).expect("measured output proof");
            let duration = start.elapsed();
            let authorized = proven.apply_signatures(&mut rng, digest, &[]).expect("measured signatures");
            (authorized, duration)
        });
        let bundle = decode_real_bundle(&bundle);
        assert_eq!(ffi_status(&bundle, |_| {}), ffi::AbiStatus::UNO_CRYPTO_OK as u32);
        export_abi_fixture(&bundle, "output-only.bin");
        assert_eq!(ffi_status(&bundle, |r| r.abi_version = 1), ffi::AbiStatus::UNO_CRYPTO_ARGUMENTS as u32);
        assert_eq!(ffi_status(&bundle, |r| r.profile = 0), ffi::AbiStatus::UNO_CRYPTO_ARGUMENTS as u32);
        assert_eq!(ffi_status(&bundle, |r| r.context = 6), ffi::AbiStatus::UNO_CRYPTO_ARGUMENTS as u32);
        assert_eq!(ffi_status(&bundle, |r| r.fee_lo = 1), ffi::AbiStatus::UNO_CRYPTO_ARGUMENTS as u32);
        assert_eq!(ffi_status(&bundle, |r| r.sighash = [43; 32]), ffi::AbiStatus::UNO_CRYPTO_VERIFY as u32);
        assert_eq!(ffi_status(&bundle, |r| r.flags = 255), ffi::AbiStatus::UNO_CRYPTO_DECODE as u32);
        assert_eq!(verifier.verify_bundle(&bundle, &digest, 2, 7264), Ok(()));
        use context::{ContextError, PublicContext};
        for context in [
            PublicContext::ShieldClaim { amount: 5000 },
            PublicContext::WithdrawalRefund { amount: 5000 },
            PublicContext::Genesis { amount: 5000 },
            PublicContext::PrivateFeeDistribution { amount: 5000 },
        ] {
            assert_eq!(verifier.verify_in_context(&bundle, context, &digest, 2, 7264), Ok(()));
        }
        assert_eq!(
            verifier.verify_in_context(
                &bundle,
                PublicContext::ShieldClaim { amount: 5001 },
                &digest,
                2,
                7264
            ),
            Err(VerificationError::Context(ContextError::ValueBalance))
        );

        // Recover an actual output and spend it from the complete action tree,
        // including the padded output at its real position.
        // This uses the dependency's test encryption, not the required hybrid profile.
        let fvk = FullViewingKey::from(&sk);
        let (note, _, _) = bundle
            .decrypt_output_with_key(
                metadata.output_action_index(0).expect("real output index"),
                &fvk.to_ivk(Scope::External),
            )
            .expect("recover real note");
        assert_eq!(note.value(), NoteValue::from_raw(5000));
        let commitments: Vec<_> = bundle.actions().iter().map(|action| action.cmx().to_bytes()).collect();
        let note_tree = tree::NoteTree::default().append_batch(&commitments, 0).expect("action tree");
        assert_eq!(note_tree.next_position(), 2);
        let real_output_index = metadata.output_action_index(0).expect("output position");
        assert!(real_output_index < 2);
        let sibling = MerkleHashOrchard::from_cmx(bundle.actions()[real_output_index ^ 1].cmx());
        let path = MerklePath::from_parts(
            u32::try_from(real_output_index).expect("output index"),
            std::array::from_fn(|level| {
                if level == 0 { sibling } else {
                    MerkleHashOrchard::empty_root(u8::try_from(level).expect("tree level").into())
                }
            }),
        );
        let anchor = path.root(note.commitment().into());
        assert_eq!(anchor.to_bytes(), note_tree.root());
        let restored_tree = tree::NoteTree::restore(&note_tree.snapshot()).expect("restore action tree");
        assert_eq!(restored_tree.root(), anchor.to_bytes());
        let mut spender = Builder::new(
            BundleType::DEFAULT,
            BundleVersion::orchard_v2(),
            BundleVersion::orchard_v2().default_flags(),
            anchor,
        )
        .expect("spend builder");
        spender.add_spend(fvk, note, path).expect("real spend");
        spender
            .add_output(None, recipient, NoteValue::from_raw(4900), [0; 512])
            .expect("change output");
        let (unsigned_spend, spend_metadata) =
            spender.build::<i64>(&mut rng).expect("spend build").expect("nonempty spend");
        assert_eq!(*unsigned_spend.value_balance(), 100);
        let real_spend_index = spend_metadata.spend_action_index(0).expect("real spend index");
        let proven_spend = unsigned_spend
            .clone()
            .create_proof(&pk, &mut rng)
            .expect("spend proof");
        let spent = proven_spend.clone()
            .apply_signatures(&mut rng, digest, &[SpendAuthorizingKey::from(&sk)])
            .expect("real spend authorization");
        assert_eq!(verifier.verify_bundle(&spent, &digest, 2, 7264), Ok(()));
        {
            use transfer_transcript::*;
            let header = test_header();
            let limits = TranscriptLimits { max_actions: 2, max_proof_bytes: 7264, kem_ciphertext_bytes: 4 };
            // Opaque transcript test bytes, not a working hybrid encryption profile.
            let kem: &[&[u8]] = &[&[31;4], &[32;4]];
            let actions = encoded_actions(&spent);
            let raw = decode::EncodedBundle { profile: spent.bundle_version(), flags: spent.flag_byte(),
                value_balance: *spent.value_balance(), anchor: spent.anchor().to_bytes(), actions: &actions,
                proof: spent.authorization().proof().as_ref(), binding_signature: spent.authorization().binding_signature().into() };
            let digests = transfer_digests(&header, &raw, kem, limits).expect("signing transcript");
            let signed = proven_spend.apply_signatures(&mut rng, digests.sighash, &[SpendAuthorizingKey::from(&sk)])
                .expect("transcript authorization");
            let signed_actions = encoded_actions(&signed);
            let signed_raw = decode::EncodedBundle { actions: &signed_actions,
                binding_signature: signed.authorization().binding_signature().into(), ..raw };
            let accepted = verify_transfer(&verifier, &header.domain, &header, &signed_raw, kem, limits)
                .expect("verified transcript");
            assert_eq!(accepted.txid, digests.txid);
            assert_ne!(accepted.authorization, digests.authorization);
            let mut changed = header.clone(); changed.nonce[0] ^= 1;
            assert!(matches!(verify_transfer(&verifier, &header.domain, &changed, &signed_raw, kem, limits),
                             Err(TranscriptError::Verification(VerificationError::SpendSignature))));
            assert!(matches!(verify_transfer(&verifier, &header.domain, &header, &signed_raw, &[&[30;4], &[32;4]], limits),
                             Err(TranscriptError::Verification(VerificationError::SpendSignature))));
            changed = header.clone(); changed.domain.network_id[0] ^= 1;
            assert_eq!(verify_transfer(&verifier, &header.domain, &changed, &signed_raw, kem, limits), Err(TranscriptError::Domain));
        }
        let spend_outputs: Vec<_> = spent.actions().iter().map(|action| action.cmx().to_bytes()).collect();
        let next_tree = restored_tree.append_batch(&spend_outputs, 0).expect("spend output append");
        assert_eq!(next_tree.next_position(), 4);
        assert_eq!(tree::NoteTree::restore(&next_tree.snapshot()).expect("next tree").root(), next_tree.root());
        assert_eq!(restored_tree.next_position(), 2);
        measure_proofs("spend", proving_samples, &verifier, || {
            let unproven = unsigned_spend.clone();
            let start = std::time::Instant::now();
            let proven = unproven.create_proof(&pk, &mut rng).expect("measured spend proof");
            let duration = start.elapsed();
            let authorized = proven
                .apply_signatures(&mut rng, digest, &[SpendAuthorizingKey::from(&sk)])
                .expect("measured spend authorization");
            (authorized, duration)
        });
        let spent = decode_real_bundle(&spent);
        assert_eq!(ffi_status(&spent, |_| {}), ffi::AbiStatus::UNO_CRYPTO_OK as u32);
        export_abi_fixture(&spent, "spend.bin");
        assert_eq!(verifier.verify_bundle(&spent, &digest, 2, 7264), Ok(()));
        assert_eq!(
            verifier.verify_in_context(
                &spent,
                PublicContext::Transfer { fee: 100 },
                &digest,
                2,
                7264
            ),
            Ok(())
        );
        assert_eq!(
            verifier.verify_in_context(
                &spent,
                PublicContext::Unshield { amount: 80, fee: 20 },
                &digest,
                2,
                7264
            ),
            Ok(())
        );
        assert_eq!(
            verifier.verify_in_context(
                &spent,
                PublicContext::Transfer { fee: 101 },
                &digest,
                2,
                7264
            ),
            Err(VerificationError::Context(ContextError::ValueBalance))
        );
        let wrong_balance = spent
            .clone()
            .try_map_value_balance(|_| Ok::<i64, std::convert::Infallible>(101))
            .expect("typed balance change");
        assert_eq!(
            verifier.verify_bundle(&wrong_balance, &digest, 2, 7264),
            Err(VerificationError::BindingSignature)
        );
        let bad_real_spend = spent.map_authorization(
            &mut 0usize,
            |index, _, sig| {
                let result = if *index == real_spend_index { [0; 64].into() } else { sig };
                *index = index.checked_add(1).expect("action index");
                result
            },
            |_, auth| auth,
        );
        assert_eq!(
            verifier.verify_bundle(&bad_real_spend, &digest, 2, 7264),
            Err(VerificationError::SpendSignature)
        );
        assert!(verifier.verify_bundle(&bundle, &[43; 32], 2, 7264).is_err());
        let bad_spend =
            bundle.clone().map_authorization(&mut (), |_, _, _| [0; 64].into(), |_, auth| auth);
        assert_eq!(
            verifier.verify_bundle(&bad_spend, &digest, 2, 7264),
            Err(VerificationError::SpendSignature)
        );
        let bad_proof = bundle.clone().map_authorization(
            &mut (),
            |_, _, sig| sig,
            |_, auth| {
                let mut bytes = auth.proof().as_ref().to_vec();
                bytes[0] ^= 1;
                Authorized::from_parts(Proof::new(bytes), auth.binding_signature().clone())
            },
        );
        assert_eq!(
            verifier.verify_bundle(&bad_proof, &digest, 2, 7264),
            Err(VerificationError::Proof)
        );
        assert_eq!(ffi_status(&bad_proof, |_| {}), ffi::AbiStatus::UNO_CRYPTO_VERIFY as u32);
        assert_eq!(
            verifier.verify_in_context(
                &bad_proof,
                PublicContext::ShieldClaim { amount: 5000 },
                &digest,
                2,
                7264
            ),
            Err(VerificationError::Proof)
        );
        let bad_binding = bundle.map_authorization(
            &mut (),
            |_, _, sig| sig,
            |_, auth| Authorized::from_parts(auth.proof().clone(), [0; 64].into()),
        );
        assert_eq!(
            verifier.verify_bundle(&bad_binding, &digest, 2, 7264),
            Err(VerificationError::BindingSignature)
        );
    }

    #[test]
    fn valid_proof_does_not_authorize_noncanonical_output_only_anchor() {
        use orchard::{
            builder::{Builder, BundleType},
            circuit::ProvingKey,
            keys::{FullViewingKey, Scope, SpendingKey},
            value::NoteValue,
        };
        let mut rng = rand::rngs::OsRng;
        let sk = SpendingKey::from_bytes([0; 32]).expect("test spending key");
        let recipient = FullViewingKey::from(&sk).address_at(0u32, Scope::External);
        let wrong_anchor = Option::<Anchor>::from(Anchor::from_bytes([0; 32])).expect("field zero");
        assert_ne!(wrong_anchor, Anchor::empty_tree());
        let mut builder = Builder::new(
            BundleType::DEFAULT,
            BundleVersion::orchard_v2(),
            Flags::SPENDS_DISABLED,
            wrong_anchor,
        )
        .expect("output-only builder");
        builder.add_output(None, recipient, NoteValue::from_raw(5000), [0; 512]).expect("output");
        let (unsigned, _) = builder.build::<i64>(&mut rng).expect("build").expect("nonempty");
        let pk = ProvingKey::build(OrchardCircuitVersion::FixedPostNu6_2);
        let digest = [42; 32];
        let bundle = unsigned
            .create_proof(&pk, &mut rng)
            .expect("proof")
            .apply_signatures(&mut rng, digest, &[])
            .expect("signatures");
        let verifier = FixedVerifier::new().expect("fixed key");
        assert_eq!(*bundle.anchor(), wrong_anchor);
        assert!(bundle.verify_proof(&verifier.key).is_ok());
        for action in bundle.actions() {
            assert!(action.rk().verify(&digest, action.authorization()).is_ok());
        }
        assert!(bundle
            .binding_validating_key()
            .verify(&digest, bundle.authorization().binding_signature())
            .is_ok());
        assert_eq!(
            verifier.verify_bundle(&bundle, &digest, 2, 7264),
            Err(VerificationError::NonCanonicalAnchor)
        );
    }

    #[test]
    fn constructed_key_is_bound_to_fixed_profile() {
        let verifier = match FixedVerifier::new() {
            Ok(verifier) => verifier,
            Err(error) => panic!("key construction failed: {error:?}"),
        };
        assert_eq!(verifier.key.circuit_version(), OrchardCircuitVersion::FixedPostNu6_2);
        assert_eq!(verifier.check_bundle_profile(BundleVersion::orchard_v2()), Ok(()));
        for version in [
            BundleVersion::orchard_insecure_v1(),
            BundleVersion::orchard_v3(),
            BundleVersion::ironwood_v3(),
        ] {
            assert_eq!(verifier.check_bundle_profile(version), Err(UnsupportedProfile));
        }
    }

    #[test]
    fn profile_requires_both_fixed_selectors() {
        let bundles = [
            BundleVersion::orchard_v2(),
            BundleVersion::orchard_insecure_v1(),
            BundleVersion::orchard_v3(),
            BundleVersion::ironwood_v3(),
        ];
        let circuits = [
            OrchardCircuitVersion::FixedPostNu6_2,
            OrchardCircuitVersion::InsecurePreNu6_2,
            OrchardCircuitVersion::PostNu6_3,
        ];
        for (b, bundle) in bundles.into_iter().enumerate() {
            for (c, circuit) in circuits.into_iter().enumerate() {
                assert_eq!(validate_profile(bundle, circuit).is_ok(), b == 0 && c == 0);
            }
        }
    }

    #[test]
    fn proof_shape_matches_pinned_circuit_sizes() {
        assert_eq!(orchard::Proof::expected_proof_size(1), 4992);
        assert_eq!(orchard::Proof::expected_proof_size(2), 7264);
        for actions in 1..=32 {
            let size = orchard::Proof::expected_proof_size(actions);
            assert_eq!(validate_proof_shape(actions, size, 32, size), Ok(()));
            assert_eq!(
                validate_proof_shape(actions, size - 1, 32, size),
                Err(ProofShapeError::NonCanonicalLength)
            );
            assert_eq!(
                validate_proof_shape(actions, size + 1, 32, size + 1),
                Err(ProofShapeError::NonCanonicalLength)
            );
        }
    }

    #[test]
    fn proof_shape_rejects_resource_and_arithmetic_boundaries() {
        assert_eq!(
            validate_proof_shape(0, 2720, 1, 4992),
            Err(ProofShapeError::EmptyOrUnconfigured)
        );
        assert_eq!(
            validate_proof_shape(1, 4992, 0, 4992),
            Err(ProofShapeError::EmptyOrUnconfigured)
        );
        assert_eq!(validate_proof_shape(1, 4992, 1, 0), Err(ProofShapeError::EmptyOrUnconfigured));
        assert_eq!(validate_proof_shape(2, 7264, 1, 7264), Err(ProofShapeError::ActionLimit));
        assert_eq!(validate_proof_shape(1, 4992, 1, 4991), Err(ProofShapeError::ByteLimit));
        assert_eq!(
            validate_proof_shape(usize::MAX, 0, usize::MAX, usize::MAX),
            Err(ProofShapeError::LengthOverflow)
        );
        let addition_overflow = usize::MAX / 2272;
        for actions in [addition_overflow, addition_overflow + 1] {
            let wrapped_size = actions.wrapping_mul(2272).wrapping_add(2720);
            assert_eq!(
                validate_proof_shape(actions, wrapped_size, usize::MAX, usize::MAX),
                Err(ProofShapeError::LengthOverflow)
            );
        }
    }
}
