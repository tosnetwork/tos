fn main() {
    println!("cargo::rustc-check-cfg=cfg(tos_mobile_fee_core)");
    println!("cargo::rustc-cfg=tos_mobile_fee_core");
    // Shared source has optional desktop native-verifier tests. They remain
    // disabled here; this package provides state, not a crypto backend.
    println!("cargo::rustc-check-cfg=cfg(feature, values(\"native-wallet-signer\"))");
}
