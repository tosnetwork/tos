//! Offline StateDb compatibility boundary. Restoration is not enabled by this crate.
//! Native access requires the vendored build explicitly; schema keys are usable without it.
use anyhow::Result;
use sha2::{Digest, Sha256};

#[cfg(feature = "native")]
mod native;
#[cfg(feature = "native")]
pub use native::OfflineStore;

/// A typed key encoded by the same generated schema as the engine.
#[derive(Clone, Debug)]
pub enum StateKey {
    Version,
    Init,
    Gc,
    ShardClient,
    DestroyedSessions,
    Hardforks,
    AsyncSerializer,
    PersistentDescriptions,
    PersistentShards(u32),
    PendingObserverCleanup,
    PendingValidatorCleanup([u8; 32]),
}
impl StateKey {
    pub fn bytes(&self) -> Result<Vec<u8>> {
        use tl_api::tos::db::state::{Key, key::key::PersistentStateDescriptionShards};
        let key = match self {
            Self::Version => Key::Db_State_Key_DbVersion,
            Self::Init => Key::Db_State_Key_InitBlockId,
            Self::Gc => Key::Db_State_Key_GcBlockId,
            Self::ShardClient => Key::Db_State_Key_ShardClient,
            Self::DestroyedSessions => Key::Db_State_Key_DestroyedSessions,
            Self::Hardforks => Key::Db_State_Key_Hardforks,
            Self::AsyncSerializer => Key::Db_State_Key_AsyncSerializer,
            Self::PersistentDescriptions => Key::Db_State_Key_PersistentStateDescriptionsList,
            Self::PersistentShards(seqno) => Key::Db_State_Key_PersistentStateDescriptionShards(
                PersistentStateDescriptionShards {
                    masterchain_seqno: i32::from_le_bytes(seqno.to_le_bytes()),
                },
            ),
            Self::PendingObserverCleanup => {
                return Ok(b"tos.state.pending_consensus_db_cleanup".to_vec());
            }
            Self::PendingValidatorCleanup(id) => {
                let mut key = b"tos.state.pending_validator_consensus_db_cleanup.".to_vec();
                const HEX: &[u8] = b"0123456789ABCDEF";
                for byte in id {
                    key.push(HEX[usize::from(byte >> 4)]);
                    key.push(HEX[usize::from(byte & 15)]);
                }
                return Ok(key);
            }
        };
        let boxed = tl_api::serialize_boxed(&key)?;
        if matches!(self, Self::Version) { Ok(boxed) } else { Ok(Sha256::digest(boxed).to_vec()) }
    }
}
