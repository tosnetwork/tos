/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! Emits the cross-language vectors for work package D.
//!
//! The TypeScript wallet and this one must agree, and the way to establish
//! that is not for both to be read against the profile by the same person.
//! This writes down what the Rust implementation produces for fixed inputs --
//! keys, descriptors, sealed payloads, validation outcomes -- and the
//! TypeScript tests are held to it.
//!
//! Every value here is derived, so the file is regenerated rather than edited.
//! A vector that has to be updated by hand is a vector that will be updated to
//! match whatever the code now does.

use std::io::Write as _;

use ark_ff::PrimeField;
use shielded_pool_circuit::field::Fr;
use shielded_pool_circuit::{notes, wire};
use shielded_pool_wallet::delivery::{self, Kind, Plaintext};
use shielded_pool_wallet::descriptor::Descriptor;
use shielded_pool_wallet::import::{import, ChainSlot};
use shielded_pool_wallet::keys::{fr_be32, PoolInstance};
use shielded_pool_wallet::scan::{self, ObservedOutput};

/// A field element as the decimal string `BigInt` reads.
fn dec(value: Fr) -> String {
    let mut digits = vec![0u8];
    for byte in fr_be32(value) {
        let mut carry = u32::from(byte);
        for digit in digits.iter_mut() {
            let next = u32::from(*digit) * 256 + carry;
            *digit = (next % 10) as u8;
            carry = next / 10;
        }
        while carry > 0 {
            digits.push((carry % 10) as u8);
            carry /= 10;
        }
    }
    digits.iter().rev().map(|d| char::from(b'0' + d)).collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// A payload is 1233 bytes and there are several of them; only their digests
/// go in the file, together with enough of the head to catch a wrong prefix.
fn digest(bytes: &[u8]) -> String {
    hex(&fr_be32(wire::output_data_hash(bytes)))
}


/// One scan's worth of observed outputs, and what a restored wallet makes of
/// them.
///
/// The scenario is chosen so that every rule of section 2.5 has a case:
/// indices with gaps between them, a dummy that consumes an index without
/// carrying balance, somebody else's payload that must leave no trace at all,
/// two notes at one index because a payer reused a descriptor, and a payload
/// that opens and is then refused because its fields are not ones this wallet
/// derives.
fn recovery_vector(seed: &[u8; 32], other_seed: &[u8; 32], domain: Fr) -> String {
    let wallet = PoolInstance::new(seed, domain);
    let stranger = PoolInstance::new(other_seed, domain);

    struct Observed {
        slot: u8,
        sealed: Vec<u8>,
        output_data_hash: Fr,
        note_body: Fr,
    }

    let mut observed: Vec<Observed> = Vec::new();
    let mut note = |instance: &PoolInstance, kind: Kind, index: u64, amount: u128,
                    secret: u64, slot: u8, break_owner: bool| {
        let plaintext = Plaintext {
            slot,
            kind,
            amount,
            note_secret: Fr::from(secret),
            owner_nf_key_hash: if break_owner {
                Fr::from(1u64)
            } else {
                match kind {
                    Kind::Dummy => shielded_pool_circuit::domains::dummy_owner_nf_hash(),
                    _ => instance.owner_nf_key_hash(index).expect("a hash"),
                }
            },
            note_key_index: index,
            pq_auth_key_hash: instance.pq_auth_key_hash(index).expect("a hash"),
        };
        let sealed = delivery::seal(
            &instance.mlkem_encapsulation_key().expect("a key"),
            domain,
            &plaintext,
        )
        .expect("seal");
        let owner = notes::owner_commitment(
            plaintext.owner_nf_key_hash,
            plaintext.pq_auth_key_hash,
            plaintext.note_secret,
        );
        let output_data_hash = wire::output_data_hash(&sealed);
        observed.push(Observed {
            slot,
            sealed,
            output_data_hash,
            note_body: notes::note_body_commitment(owner, Fr::from(amount), output_data_hash),
        });
    };

    // Indices 0 and 4, so a wallet that merely counted would reissue 1.
    note(&wallet, Kind::Ordinary, 0, 1_000, 0xa1, 0, false);
    note(&wallet, Kind::Ordinary, 4, 2_000, 0xa2, 1, false);
    // A dummy at 6: no balance, index consumed all the same.
    note(&wallet, Kind::Dummy, 6, 0, 0xa3, 2, false);
    // Somebody else's, which must not open and must leave no diagnostic.
    note(&stranger, Kind::Ordinary, 0, 9_999, 0xa4, 0, false);
    // A payer reusing a descriptor: a second note at index 4.
    note(&wallet, Kind::Ordinary, 4, 3_000, 0xa5, 1, false);
    // Ours, opens, and is then refused: the owner hash is not one we derive.
    note(&wallet, Kind::Ordinary, 2, 500, 0xa6, 0, true);

    let outputs: Vec<ObservedOutput> = observed
        .iter()
        .map(|entry| ObservedOutput {
            slot: entry.slot,
            output_data: entry.sealed.clone(),
            chain: ChainSlot {
                output_data_hash: entry.output_data_hash,
                note_body: entry.note_body,
            recovered: None,
            },
        })
        .collect();
    let recovered = scan::recover(&wallet, &outputs).expect("recover");

    let mut out = String::from("{\n");
    out.push_str(&format!("    \"seed\": \"{}\",\n", hex(seed)));
    out.push_str(&format!("    \"execution_domain\": \"{}\",\n", dec(domain)));
    out.push_str("    \"outputs\": [\n");
    for (position, entry) in observed.iter().enumerate() {
        if position > 0 {
            out.push_str(",\n");
        }
        out.push_str("      {\n");
        out.push_str(&format!("        \"slot\": {},\n", entry.slot));
        out.push_str(&format!("        \"sealed\": \"{}\",\n", hex(&entry.sealed)));
        out.push_str(&format!(
            "        \"output_data_hash\": \"{}\",\n",
            dec(entry.output_data_hash)
        ));
        out.push_str(&format!("        \"note_body\": \"{}\"\n", dec(entry.note_body)));
        out.push_str("      }");
    }
    out.push_str("\n    ],\n");
    out.push_str("    \"expected\": {\n");
    out.push_str(&format!("      \"balance\": \"{}\",\n", recovered.balance()));
    out.push_str(&format!(
        "      \"next_note_key_index\": {},\n",
        recovered.next_note_key_index
    ));
    out.push_str("      \"notes\": [\n");
    for (position, found) in recovered.notes.iter().enumerate() {
        if position > 0 {
            out.push_str(",\n");
        }
        out.push_str(&format!(
            "        {{ \"kind\": \"{:?}\", \"index\": {}, \"amount\": \"{}\", \"spendable\": {}, \"note_body\": \"{}\" }}",
            found.kind, found.note_key_index, found.amount, found.spendable,
            dec(found.note_body)
        ));
    }
    out.push_str("\n      ],\n");
    out.push_str("      \"reused\": [");
    for (position, index) in recovered.reused.iter().enumerate() {
        if position > 0 {
            out.push_str(", ");
        }
        out.push_str(&index.to_string());
    }
    out.push_str("],\n");
    out.push_str("      \"diagnostics\": [");
    for (position, diagnostic) in recovered.diagnostics.iter().enumerate() {
        if position > 0 {
            out.push_str(", ");
        }
        out.push_str(&format!("\"{:?}\"", diagnostic.why));
    }
    out.push_str("]\n    }\n  }");
    out
}

fn main() {
    let path = std::env::args().nth(1).unwrap_or_else(|| {
        eprintln!("usage: wallet-vectors <output.json>");
        std::process::exit(2);
    });

    // Two seeds and two domains, so every claim about separation has both
    // halves present in the file.
    let seeds: [[u8; 32]; 2] = [[0x11; 32], [0x12; 32]];
    let domains = [Fr::from(0x5348_4c44_5f41u64), Fr::from(0x5348_4c44_5f42u64)];

    let mut out = String::new();
    out.push_str("{\n  \"note\": \"Generated by tools/shielded-pool-wallet/src/bin/wallet-vectors.rs. Do not edit by hand.\",\n");
    out.push_str("  \"instances\": [\n");
    let mut first_instance = true;
    for (seed_index, seed) in seeds.iter().enumerate() {
        for (domain_index, domain) in domains.iter().enumerate() {
            let instance = PoolInstance::new(seed, *domain);
            if !first_instance {
                out.push_str(",\n");
            }
            first_instance = false;
            out.push_str("    {\n");
            out.push_str(&format!("      \"seed\": \"{}\",\n", hex(seed)));
            out.push_str(&format!("      \"execution_domain\": \"{}\",\n", dec(*domain)));
            let (d, z) = instance.mlkem_seed();
            out.push_str(&format!("      \"mlkem_d\": \"{}\",\n", hex(&d)));
            out.push_str(&format!("      \"mlkem_z\": \"{}\",\n", hex(&z)));
            out.push_str(&format!(
                "      \"mlkem_encapsulation_key_sha\": \"{}\",\n",
                hex(&fr_be32(wire::pq_auth_key_hash(
                    &instance.mlkem_encapsulation_key().expect("a key")
                )))
            ));
            out.push_str("      \"indices\": [\n");
            for (position, index) in [0u64, 1, 7, 1_000_000].iter().enumerate() {
                if position > 0 {
                    out.push_str(",\n");
                }
                out.push_str("        {\n");
                out.push_str(&format!("          \"index\": {index},\n"));
                out.push_str(&format!(
                    "          \"owner_nf_key\": \"{}\",\n",
                    dec(instance.owner_nf_key(*index).expect("a key"))
                ));
                out.push_str(&format!(
                    "          \"owner_nf_key_hash\": \"{}\",\n",
                    dec(instance.owner_nf_key_hash(*index).expect("a hash"))
                ));
                out.push_str(&format!(
                    "          \"mldsa_seed\": \"{}\",\n",
                    hex(&instance.mldsa_seed(*index))
                ));
                out.push_str(&format!(
                    "          \"mldsa_public_key_hash\": \"{}\",\n",
                    dec(instance.pq_auth_key_hash(*index).expect("a hash"))
                ));
                let descriptor = Descriptor::issue(&instance, *index).expect("a descriptor");
                out.push_str(&format!(
                    "          \"descriptor_sha\": \"{}\"\n",
                    digest(&descriptor.to_bytes())
                ));
                out.push_str("        }");
            }
            out.push_str("\n      ]\n    }");
            let _ = (seed_index, domain_index);
        }
    }
    out.push_str("\n  ],\n");

    // Delivery. The ML-KEM encapsulation is randomised, so a sealed payload
    // cannot be a fixed vector; what is fixed is the plaintext encoding and
    // what a wallet makes of a payload it opens.
    let instance = PoolInstance::new(&seeds[0], domains[0]);
    out.push_str("  \"plaintexts\": [\n");
    let cases: [(Kind, u128, u64, u8); 3] = [
        (Kind::Ordinary, 1_000_000_000, 3, 0),
        (Kind::Dummy, 0, 4, 2),
        (Kind::Recovery, 0, 5, 1),
    ];
    for (position, (kind, amount, index, slot)) in cases.iter().enumerate() {
        if position > 0 {
            out.push_str(",\n");
        }
        let plaintext = Plaintext {
            slot: *slot,
            kind: *kind,
            amount: *amount,
            note_secret: Fr::from(0xc0ffeeu64 + index),
            owner_nf_key_hash: match kind {
                Kind::Dummy => shielded_pool_circuit::domains::dummy_owner_nf_hash(),
                _ => instance.owner_nf_key_hash(*index).expect("a hash"),
            },
            note_key_index: *index,
            pq_auth_key_hash: instance.pq_auth_key_hash(*index).expect("a hash"),
        };
        let encoded = plaintext.to_bytes();
        let sealed = delivery::seal(
            &instance.mlkem_encapsulation_key().expect("a key"),
            domains[0],
            &plaintext,
        )
        .expect("seal");
        let owner = notes::owner_commitment(
            plaintext.owner_nf_key_hash,
            plaintext.pq_auth_key_hash,
            plaintext.note_secret,
        );
        let output_data_hash = wire::output_data_hash(&sealed);
        let note_body =
            notes::note_body_commitment(owner, Fr::from(plaintext.amount), output_data_hash);
        let slot_view = ChainSlot {
            output_data_hash,
            note_body: match kind {
                Kind::Recovery => {
                    wire::recovery_template_hash(owner, output_data_hash)
                }
                _ => note_body,
            },
            recovered: None,
        };
        let imported = import(&instance, &plaintext, &slot_view)
            .expect("import")
            .expect("a valid payload");

        out.push_str("    {\n");
        out.push_str(&format!("      \"kind\": \"{kind:?}\",\n"));
        out.push_str(&format!("      \"slot\": {slot},\n"));
        out.push_str(&format!("      \"note_key_index\": {index},\n"));
        out.push_str(&format!("      \"amount\": \"{amount}\",\n"));
        out.push_str(&format!(
            "      \"note_secret\": \"{}\",\n",
            dec(plaintext.note_secret)
        ));
        out.push_str(&format!("      \"plaintext_bytes\": \"{}\",\n", hex(&encoded)));
        out.push_str(&format!("      \"sealed_length\": {},\n", sealed.len()));
        // The whole sealed payload. Sealing is randomised, so this cannot be
        // compared byte for byte -- but opening it is deterministic, and a
        // TypeScript wallet that opens what this one sealed is the only
        // evidence that two ML-KEM implementations interoperate.
        out.push_str(&format!("      \"sealed\": \"{}\",\n", hex(&sealed)));
        out.push_str(&format!("      \"owner_commitment\": \"{}\",\n", dec(owner)));
        out.push_str(&format!(
            "      \"note_body_from_chain_hash\": \"{}\",\n",
            dec(imported.note_body)
        ));
        out.push_str(&format!("      \"spendable\": {}\n", imported.spendable));
        out.push_str("    }");
    }
    out.push_str("\n  ],\n");

    // A whole scan. The TypeScript has no chain to check itself against, so
    // what pins it is that the same observed outputs produce the same
    // conclusions: which notes, which balance, which index next, which
    // indices burnt, and which payloads opened and were then refused.
    out.push_str("  \"recovery\": ");
    out.push_str(&recovery_vector(&seeds[0], &seeds[1], domains[0]));
    out.push_str(",\n");

    // The derived public inputs, which the TypeScript has to compute the same
    // way to build a transaction the contract will accept.
    out.push_str("  \"derived_inputs\": {\n");
    let payload: Vec<u8> = (0..1233u32).map(|i| (i as u8) ^ 0x21).collect();
    out.push_str(&format!("    \"payload_sha\": \"{}\",\n", digest(&payload)));
    out.push_str(&format!(
        "    \"output_data_hash\": \"{}\",\n",
        dec(wire::output_data_hash(&payload))
    ));
    let key = instance.mldsa_public_key(0).expect("a key");
    out.push_str(&format!(
        "    \"pq_auth_key_hash\": \"{}\",\n",
        dec(wire::pq_auth_key_hash(&key))
    ));
    out.push_str(&format!(
        "    \"public_recipient_hash\": \"{}\",\n",
        dec(wire::public_recipient_hash(&[0x42; 32]))
    ));
    out.push_str(&format!(
        "    \"execution_domain\": \"{}\",\n",
        dec(wire::execution_domain(-239, &[0x7a; 32]))
    ));
    out.push_str(&format!(
        "    \"recovery_template_hash\": \"{}\"\n",
        dec(wire::recovery_template_hash(Fr::from(0x5eedu64), Fr::from(0x1234u64)))
    ));
    out.push_str("  }\n}\n");

    let mut file = std::fs::File::create(&path).expect("create the vector file");
    file.write_all(out.as_bytes()).expect("write the vector file");
    eprintln!("wrote {path}");
}
