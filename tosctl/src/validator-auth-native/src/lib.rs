pub mod cells;
pub mod certificate_proof;
pub mod committee;
pub mod committee_proof;
pub mod proof;
pub mod registry;
pub mod registry_view;
use tos_validator_auth::codec::Error;
pub(crate) fn native<T>(value: chain_block::Result<T>) -> Result<T, Error> {
    value.map_err(|_| Error("native-cell"))
}
