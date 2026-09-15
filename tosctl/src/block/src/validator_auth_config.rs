use crate::validator_auth_profile::VALIDATOR_AUTH_PROFILE_FINGERPRINT;
use crate::{error, Cell, CellType, ConfigParams, Result, Serializable, SliceData};

struct Header {
    domain: Vec<u8>,
    revision: u64,
    identities: Cell,
    keys: Cell,
}
fn need(ok: bool, reason: &str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(error!("{}", reason))
    }
}
fn param(config: &ConfigParams, at: u32) -> Result<Option<Cell>> {
    match config.config_params.get(at.write_to_bitstring()?)? {
        None => Ok(None),
        Some(value) => {
            need(
                value.remaining_bits() == 0 && value.remaining_references() == 1,
                "validator-auth-parameter",
            )?;
            Ok(Some(value.reference(0)?))
        }
    }
}
fn required(config: &ConfigParams, at: u32, reason: &str) -> Result<Cell> {
    param(config, at)?.ok_or_else(|| error!("{}", reason))
}
fn read_registry(registry: Cell) -> Result<Header> {
    need(registry.level_mask().mask() == 0, "validator-auth-registry")?;
    let mut root = SliceData::load_cell(registry)?;
    need(
        root.cell_type() == CellType::Ordinary
            && root.remaining_bits() == 880
            && root.remaining_references() == 4
            && root.get_next_u32()? == 0x76617131
            && root.get_next_u16()? == 1,
        "validator-auth-registry",
    )?;
    let domain = root.get_next_bits(256)?;
    need(
        domain != [0; 32] && root.get_next_bits(256)? == VALIDATOR_AUTH_PROFILE_FINGERPRINT,
        "validator-auth-profile",
    )?;
    let revision = root.get_next_u64()?;
    need(root.get_next_bits(256)? != [0; 32], "validator-auth-registry")?;
    let identities = root.checked_drain_reference()?;
    let keys = root.checked_drain_reference()?;
    let dictionary_shape = |cell: Cell| -> Result<bool> {
        let mut s = SliceData::load_cell(cell)?;
        Ok(s.cell_type() == CellType::Ordinary
            && s.remaining_bits() == 1
            && s.remaining_references() == usize::from(s.get_next_bit()?))
    };
    need(
        dictionary_shape(identities.clone())?
            && dictionary_shape(keys.clone())?
            && dictionary_shape(root.checked_drain_reference()?)?,
        "validator-auth-dictionary",
    )?;
    let mut control = SliceData::load_cell(root.checked_drain_reference()?)?;
    need(
        control.cell_type() == CellType::Ordinary
            && control.remaining_bits() == 32
            && control.remaining_references() == 2
            && control.get_next_u32()? == 0x76616331
            && dictionary_shape(control.checked_drain_reference()?)?
            && dictionary_shape(control.checked_drain_reference()?)?,
        "validator-auth-control",
    )?;
    Ok(Header { domain, revision, identities, keys })
}
fn read(config: &ConfigParams) -> Result<Option<Header>> {
    let Some(cap) = param(config, 8)? else {
        return Ok(None);
    };
    let mut cap = SliceData::load_cell(cap)?;
    need(
        cap.cell_type() == CellType::Ordinary
            && cap.remaining_bits() == 104
            && cap.remaining_references() == 0
            && cap.get_next_byte()? == 0xc4,
        "validator-auth-config8",
    )?;
    let version = cap.get_next_u32()?;
    if cap.get_next_u64()? & 1024 == 0 {
        return Ok(None);
    }
    need(version >= 16, "validator-auth-version")?;
    for at in [9, 10] {
        let dictionary = crate::HashmapE::with_hashmap(
            32,
            Some(required(config, at, "validator-auth-required")?),
        );
        let value = dictionary
            .get(46u32.write_to_bitstring()?)?
            .ok_or_else(|| error!("validator-auth-required"))?;
        need(
            value.remaining_bits() == 0 && value.remaining_references() == 0,
            "validator-auth-required",
        )?;
    }
    let mut count = SliceData::load_cell(required(config, 16, "validator-auth-count")?)?;
    need(
        count.cell_type() == CellType::Ordinary
            && count.remaining_bits() == 48
            && count.remaining_references() == 0,
        "validator-auth-count",
    )?;
    let maximum = count.get_next_u16()?;
    let main = count.get_next_u16()?;
    let minimum = count.get_next_u16()?;
    need(
        maximum <= 400 && main <= maximum && minimum >= 1 && minimum <= main,
        "validator-auth-count",
    )?;
    read_registry(required(config, 46, "validator-auth-registry")?).map(Some)
}
/// Structural admission accompanies native execution authorization and complete
/// registry validation; it cannot supply either of those independent authorities.
pub fn validate_validator_auth_config(config: &ConfigParams) -> Result<()> {
    read(config).map(|_| ())
}

pub fn validate_validator_auth_transition(
    before: &ConfigParams,
    after: &ConfigParams,
) -> Result<()> {
    let old = read(before)?;
    let next = read(after)?;
    let (old, next) = match (old, next) {
        (None, None) => return Ok(()),
        (None, Some(_)) => return Err(error!("validator-auth-transition-unapproved")),
        (Some(_), None) => return Err(error!("validator-auth-downgrade")),
        (Some(old), Some(next)) => (old, next),
    };
    need(old.domain == next.domain, "validator-auth-domain")?;
    let changed = old.identities.repr_hash() != next.identities.repr_hash()
        || old.keys.repr_hash() != next.keys.repr_hash();
    need(
        next.revision.checked_sub(old.revision) == Some(u64::from(changed)),
        "validator-auth-revision",
    )?;
    Ok(())
}

/// Bounded native root/header admission. Complete archive semantics belong to
/// validated checkpoint loading and authenticated operation replay.
pub fn validate_validator_auth_root_shape(root: &Cell) -> Result<()> {
    read_registry(root.clone()).map(|_| ())
}
