pub mod cells;
pub mod committee;
pub mod proof;
pub mod registry;
use tos_validator_auth::codec::Error;
pub(crate) fn native<T>(value: chain_block::Result<T>) -> Result<T, Error> {
    value.map_err(|_| Error("native-cell"))
}
