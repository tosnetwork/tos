//! Immutable inputs used by the installed traffic generator. Neither getter
//! opens the build checkout at runtime. include_str! also makes Cargo rebuild
//! the consumer when a contract/fixture changes.

pub const POOL_SOURCE: &str =
    include_str!("../../../../crypto/smartcont/tos-shielded-pool-v1.fc");
pub const DEVELOPMENT_FIXTURE: &str = include_str!("../../fixtures/groth16-development.json");

pub fn gas_ceiling(name: &str) -> Result<i64, String> {
    let needle = format!("int {name}() asm \"");
    let mut declarations = POOL_SOURCE.match_indices(&needle);
    let (at, _) = declarations.next().ok_or_else(|| format!("{name} is not declared in the pool"))?;
    if declarations.next().is_some() {
        return Err(format!("{name} is declared more than once"));
    }
    let rest = &POOL_SOURCE[at + needle.len()..];
    let end = rest.find(" PUSHINT").ok_or_else(|| format!("{name} is not a PUSHINT constant"))?;
    let value: i64 = rest[..end].trim().parse().map_err(|error| format!("{name}: {error}"))?;
    if value <= 0 {
        return Err(format!("{name} must be positive"));
    }
    Ok(value)
}
