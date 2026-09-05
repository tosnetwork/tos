use std::{env, error::Error, fs, path::PathBuf};

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
    fs::write(PathBuf::from(env::var("OUT_DIR")?).join("uno_crypto.h"), &generated)?;
    if let Some(output) = env::var_os("UNO_CRYPTO_HEADER_OUT") {
        // Explicit maintenance export only; ordinary builds never rewrite source files.
        fs::write(output, &generated)?;
    }
    if fs::read(root.join("include/uno_crypto.h"))? != generated {
        return Err("Rust ABI and committed header differ; regenerate explicitly as described in ABI.md".into());
    }
    Ok(())
}
