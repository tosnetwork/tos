use std::{env, error::Error, fs, io::Write, path::PathBuf};

fn main() -> Result<(), Box<dyn Error>> {
    let root = PathBuf::from(env::var("CARGO_MANIFEST_DIR")?);
    println!("cargo:rerun-if-changed=src");
    println!("cargo:rerun-if-changed=cbindgen.toml");
    println!("cargo:rerun-if-changed=include/uno_crypto.h");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=UNO_CRYPTO_HEADER_OUT");
    let bindings = cbindgen::Builder::new()
        .with_crate(&root)
        .with_config(cbindgen::Config::from_file(root.join("cbindgen.toml"))?)
        .generate()?;
    let mut generated = Vec::new();
    bindings.write(&mut generated);
    let artifact = PathBuf::from(env::var("OUT_DIR")?).join("uno_crypto.h");
    fs::write(&artifact, &generated)?;
    if fs::read(root.join("include/uno_crypto.h"))? != generated {
        return Err(format!("Rust ABI and committed header differ; review generated header at {}", artifact.display()).into());
    }
    if let Some(output) = env::var_os("UNO_CRYPTO_HEADER_OUT") {
        // Export only a verified copy, never overwrite an existing file or link.
        let mut file = fs::OpenOptions::new().write(true).create_new(true).open(output)?;
        file.write_all(&generated)?;
    }
    Ok(())
}
