#[cfg(panic = "abort")]
compile_error!("uno-crypto requires panic=unwind for ABI containment");

pub mod ffi;
mod relation;
mod system_encryption;
pub use relation::verify_relation;

#[cfg(test)]
mod tests;
