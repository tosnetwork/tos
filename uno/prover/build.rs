// Bind test-wallet executables to content, including dependency source and lockfiles.
fn main() {
    let manifest = std::path::PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").expect("manifest"));
    let root = manifest.parent().and_then(|p| p.parent()).expect("repository root");
    let output = std::process::Command::new("python3")
        .arg(root.join("test/uno_wallet_freshness.py"))
        .arg("--cargo").arg(root).output().expect("source identity tool");
    assert!(output.status.success(), "source identity failed: {}", String::from_utf8_lossy(&output.stderr));
    print!("{}", String::from_utf8(output.stdout).expect("source identity UTF-8"));
}
