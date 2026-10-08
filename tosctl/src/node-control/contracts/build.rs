fn main() {
    // The shared journal is also compiled by the mobile state-only crate.
    // This crate keeps all proof-bound transaction APIs enabled.
    println!("cargo::rustc-check-cfg=cfg(tos_mobile_fee_core)");
}
