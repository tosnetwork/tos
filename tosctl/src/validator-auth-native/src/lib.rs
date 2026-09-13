pub mod cells;
pub mod proof;
use tos_validator_auth::codec::Error;
pub(crate) fn native<T>(value: chain_block::Result<T>) -> Result<T, Error> {
    value.map_err(|_| Error("native-cell"))
}
