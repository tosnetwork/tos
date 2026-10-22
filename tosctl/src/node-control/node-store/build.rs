use std::{env, path::PathBuf};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-env-changed=NODE_STORE_NATIVE_DIR");
    if env::var_os("CARGO_FEATURE_NATIVE").is_none() {
        return Ok(());
    }
    let dir = PathBuf::from(env::var("NODE_STORE_NATIVE_DIR").map_err(|_| {
        "NODE_STORE_NATIVE_DIR must name this checkout's CMake-built database library directory"
    })?);
    if !dir.join("librocksdb.a").is_file() {
        return Err("build the vendored database target before building node-store".into());
    }
    println!("cargo:rustc-link-search=native={}", dir.display());
    println!("cargo:rustc-link-lib=static=rocksdb");
    println!("cargo:rustc-link-lib=dylib=stdc++");
    println!("cargo:rustc-link-lib=dylib=pthread");
    println!("cargo:rustc-link-lib=dylib=dl");
    Ok(())
}
