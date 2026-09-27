//! Structural checks shared by consumers of the generated PQ signature-set carriers.

use std::collections::HashSet;

use crate::tos::{lite_server, tos_node};

pub const SIGNATURE_BYTES: usize = 2420;
pub const MAX_SIGNERS: usize = 400;
pub const MLDSA44_ALGORITHM_ID: i32 = 1;

fn validate_pairs<'a>(
    pairs: impl IntoIterator<Item = (&'a chain_block::UInt256, i32, &'a Vec<u8>)>,
    count: usize,
) -> std::result::Result<(), &'static str> {
    if count > MAX_SIGNERS {
        return Err("signer_count");
    }
    let mut validators = HashSet::with_capacity(count);
    for (validator_id, algorithm_id, signature) in pairs {
        if algorithm_id != MLDSA44_ALGORITHM_ID {
            return Err("unsupported_algorithm");
        }
        if signature.len() != SIGNATURE_BYTES {
            return Err("signature_length");
        }
        if !validators.insert(validator_id.clone()) {
            return Err("duplicate_validator_id");
        }
    }
    Ok(())
}

pub fn validate_node(value: &tos_node::SignatureSet) -> std::result::Result<(), &'static str> {
    let tos_node::SignatureSet::TosNode_SignatureSet_SimplexPq(value) = value else {
        return Err("wrong_constructor");
    };
    validate_pairs(
        value
            .signatures
            .iter()
            .map(|pair| (&pair.validator_id, pair.algorithm_id, &pair.signature)),
        value.signatures.len(),
    )
}

pub fn validate_lite(value: &lite_server::SignatureSet) -> std::result::Result<(), &'static str> {
    let lite_server::SignatureSet::LiteServer_SignatureSet_SimplexPq(value) = value else {
        return Err("wrong_constructor");
    };
    validate_pairs(
        value
            .signatures
            .iter()
            .map(|pair| (&pair.validator_id, pair.algorithm_id, &pair.signature)),
        value.signatures.len(),
    )
}
