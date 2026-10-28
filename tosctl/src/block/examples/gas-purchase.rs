// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
//! Bounded independent gas-purchase comparison adapter.
use chain_block::GasLimitsPrices;
use std::{fs::File, io::Read};

fn main() -> anyhow::Result<()> {
    let args: Vec<_> = std::env::args().collect();
    anyhow::ensure!(args.len() == 2, "usage: gas-purchase inputs.tsv");
    let mut input = String::new();
    File::open(&args[1])?.take(8 * 1024 * 1024 + 1).read_to_string(&mut input)?;
    anyhow::ensure!(input.len() <= 8 * 1024 * 1024, "input byte bound");
    let mut count = 0;
    for line in input.lines() {
        count += 1;
        anyhow::ensure!(count <= 8192 && line.len() <= 1024, "row bound");
        let fields: Vec<_> = line.split_whitespace().collect();
        anyhow::ensure!(fields.len() == 6, "row fields");
        let name = fields[0];
        anyhow::ensure!(
            name.len() <= 64 && name.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-'),
            "row name"
        );
        anyhow::ensure!(
            fields[1..].iter().all(|v| !v.is_empty() && v.bytes().all(|c| c.is_ascii_digit())),
            "unsigned scalar"
        );
        anyhow::ensure!(
            fields[1..5].iter().all(|v| v.len() <= 20) && fields[5].len() <= 39,
            "decimal bound"
        );
        let config = GasLimitsPrices {
            gas_price: fields[1].parse()?,
            gas_limit: fields[2].parse()?,
            flat_gas_limit: fields[3].parse()?,
            flat_gas_price: fields[4].parse()?,
            ..GasLimitsPrices::default()
        };
        let threshold = config.calc_max_gas_threshold(config.gas_limit)?;
        let gas = config.calc_gas(fields[5].parse()?, config.gas_limit, threshold)?;
        println!("{name}\t{threshold}\t{gas}");
    }
    anyhow::ensure!(count != 0, "empty input");
    Ok(())
}
