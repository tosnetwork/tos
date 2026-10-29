// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
//! Bounded independent unsigned-integer codec comparison adapter.
use chain_block::{
    BuilderData, Coins, Deserializable, Serializable, SliceData, VarUInteger3, VarUInteger32,
    VarUInteger7,
};
use std::{fmt::Display, fs::File, io::Read};
fn record<T: Deserializable + Serializable + Display>(
    op: &str,
    data: &str,
    parse: fn(&str) -> anyhow::Result<T>,
) -> anyhow::Result<(bool, String, String, String)> {
    let mut skipped = "-".to_owned();
    let result: anyhow::Result<T> = if op == "read" {
        anyhow::ensure!(data.len() <= 1023, "bit bound");
        let bits = if data == "-" { "" } else { data };
        let mut raw = vec![0u8; bits.len().div_ceil(8)];
        for (i, bit) in bits.bytes().enumerate() {
            anyhow::ensure!(bit == b'0' || bit == b'1', "binary");
            raw[i / 8] |= (bit - b'0') << (7 - i % 8);
        }
        let cell = BuilderData::with_raw(raw, bits.len())?.into_cell()?;
        let mut fast = SliceData::load_cell(cell.clone())?;
        skipped = if T::skip(&mut fast).is_ok() { "1" } else { "0" }.to_owned();
        T::construct_from(&mut SliceData::load_cell(cell)?)
    } else {
        anyhow::ensure!(op == "write" && data.len() <= 90, "operation");
        parse(data)
    };
    if let Ok(value) = result {
        if let Ok(encoded) = value.serialize() {
            let hash = encoded.repr_hash().as_slice().iter().map(|b| format!("{b:02x}")).collect();
            return Ok((true, value.to_string(), hash, skipped));
        }
    }
    Ok((false, "-".to_owned(), "-".to_owned(), skipped))
}
fn main() -> anyhow::Result<()> {
    let args: Vec<_> = std::env::args().collect();
    anyhow::ensure!(args.len() == 2, "usage: varuint-rust input.tsv");
    let mut raw = Vec::new();
    File::open(&args[1])?.take(8 * 1024 * 1024 + 1).read_to_end(&mut raw)?;
    anyhow::ensure!(raw.len() <= 8 * 1024 * 1024, "byte bound");
    let input = std::str::from_utf8(&raw)?;
    let mut count = 0;
    for line in input.lines() {
        count += 1;
        anyhow::ensure!(count <= 4096 && line.len() <= 2048, "input bound");
        let f: Vec<_> = line.split_whitespace().collect();
        anyhow::ensure!(f.len() == 4, "record");
        let row = match f[2] {
            "3" => record::<VarUInteger3>(f[1], f[3], |s| {
                Ok(VarUInteger3::try_from(s.parse::<u32>()?)?)
            }),
            "7" => record::<VarUInteger7>(f[1], f[3], |s| {
                Ok(VarUInteger7::try_from(s.parse::<u64>()?)?)
            }),
            "16" => record::<Coins>(f[1], f[3], |s| Ok(Coins::try_from(s.parse::<u128>()?)?)),
            "32" => record::<VarUInteger32>(f[1], f[3], |s| Ok(s.parse::<VarUInteger32>()?)),
            _ => anyhow::bail!("type"),
        }?;
        println!("{}\t{}\t{}\t{}\t{}", f[0], u8::from(row.0), row.1, row.2, row.3);
    }
    anyhow::ensure!(count > 0, "empty input");
    Ok(())
}
