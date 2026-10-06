// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
// PUBLIC TEST KEYS ONLY. No arbitrary seed input; never use for custody or funds.
use wallet_pq_signer::{Purpose, Role, Signer};

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8] = b"0123456789abcdef";
    bytes
        .iter()
        .flat_map(|b| [DIGITS[(b >> 4) as usize] as char, DIGITS[(b & 15) as usize] as char])
        .collect()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 5 || args[1] != "--public-fixture" {
        return Err("usage: public_fixture --public-fixture <key> <purpose> <digest-hex>".into());
    }
    let (role, byte) = match args[2].as_str() {
        "primary" => (Role::Primary, 0x11),
        "next-primary" => (Role::Primary, 0x99),
        "rescue" => (Role::Rescue, 0x22),
        "next-rescue" => (Role::Rescue, 0x33),
        _ => return Err("unknown public fixture key".into()),
    };
    let purpose = match args[3].as_str() {
        "auth" => Purpose::Auth,
        "pop" => Purpose::Pop,
        "preparation" => Purpose::Preparation,
        _ => return Err("unknown purpose".into()),
    };
    if args[4].len() != 64
        || !args[4].bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("digest must be exactly 32 lowercase hex bytes".into());
    }
    let mut digest = [0; 32];
    for (index, byte) in digest.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&args[4][index * 2..index * 2 + 2], 16)?;
    }
    let mut seed = vec![byte; if role == Role::Primary { 32 } else { 48 }];
    let mut signer = Signer::import_and_wipe(role, &mut seed)?;
    let key = signer.public_key().to_vec();
    let signature = signer.sign_bound(role, &key, purpose, &digest)?;
    println!("{{\"public_key\":\"{}\",\"signature\":\"{}\"}}", hex(&key), hex(&signature));
    Ok(())
}
