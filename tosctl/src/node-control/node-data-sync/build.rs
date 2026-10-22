fn main() {
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_NATIVE_LIFECYCLE_TESTS");
    if std::env::var_os("CARGO_FEATURE_NATIVE_LIFECYCLE_TESTS").is_some()
        && std::env::var("PROFILE").as_deref() == Ok("release")
    {
        eprintln!("native-lifecycle-tests is forbidden in the release build profile");
        std::process::exit(1);
    }
}
