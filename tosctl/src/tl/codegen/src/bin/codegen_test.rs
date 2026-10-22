/*
 * Copyright (C) 2019-2023 EverX. All Rights Reserved.
 * Modifications Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This file has been modified from its original version.
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
use std::{env, path::PathBuf};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args_os().skip(1);
    let root = PathBuf::from(args.next().ok_or("usage: codegen_test REPOSITORY OUTPUT_DIRECTORY")?);
    let output = PathBuf::from(args.next().ok_or("missing generated output directory")?);
    if args.next().is_some() {
        return Err("unexpected argument".into());
    }
    tl_codegen::input::generate(tl_codegen::input::load(&root)?, &output)?;
    Ok(())
}
