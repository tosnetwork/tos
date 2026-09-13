use crate::{owner_proof::verify_owner_execution, registry::RegistryState};
use std::cell::RefCell;
use tos_validator_auth::{
    codec::{decode, encode, Error, Hash},
    context::{
        admin_session_id, make_duty, verify_identity_certificate, verify_possession, ChainContext,
    },
    lifecycle::{apply_identity_update, select_identity_keys, KeyHistory, LifecycleAuthority},
    transfer::ObjectReader,
    types::*,
    verify::RegistrySnapshot,
};
/// Independently finalized native history; a coordinate supplied by a peer is
/// only a lookup key and never selects the trusted fork.
pub trait FinalizedAnchorSource {
    fn finalized_anchor(&self, coordinate: u32) -> Result<Anchor, Error>;
}
pub struct NativeIdentityContext<'a, H> {
    pub chain: ChainContext,
    pub governing: &'a RegistrySnapshot,
    pub history: &'a H,
}
pub trait CurrentRegistry: KeyHistory {
    fn lookup_identity(&self, id: &Hash) -> Result<Option<Identity>, Error>;
    fn chain_domain(&self) -> &Hash;
    fn current_policy(&self) -> &Hash;
    fn coordinate(&self) -> u32;
}
impl CurrentRegistry for RegistryState {
    fn lookup_identity(&self, id: &Hash) -> Result<Option<Identity>, Error> {
        Ok(self.identities.get(id).cloned())
    }
    fn chain_domain(&self) -> &Hash {
        RegistryState::chain_domain(self)
    }
    fn current_policy(&self) -> &Hash {
        RegistryState::current_policy(self)
    }
    fn coordinate(&self) -> u32 {
        RegistryState::coordinate(self)
    }
}
pub struct NativeLifecycleAuthority<'a, 'b, F, H, S = RegistryState> {
    current: &'a S,
    context: &'a NativeIdentityContext<'a, H>,
    reader: RefCell<&'b mut ObjectReader<F>>,
}
impl<'a, 'b, F, H: FinalizedAnchorSource, S: CurrentRegistry>
    NativeLifecycleAuthority<'a, 'b, F, H, S>
{
    pub fn new(
        current: &'a S,
        context: &'a NativeIdentityContext<'a, H>,
        reader: &'b mut ObjectReader<F>,
    ) -> Self {
        Self { current, context, reader: RefCell::new(reader) }
    }
    pub fn validate_context(&self) -> Result<(), Error> {
        if self.current.chain_domain() != &self.context.chain.chain_domain
            || self.current.coordinate() == u32::MAX
        {
            return Err(Error("authority-current-state"));
        }
        if self.current.current_policy() != self.context.governing.policy_id() {
            return Err(Error("authority-current-policy"));
        }
        let committee = self.context.governing.committee();
        if committee.workchain != -1 || committee.shard != 1 << 63 {
            return Err(Error("authority-committee"));
        }
        let age = self
            .current
            .coordinate()
            .checked_sub(committee.anchor_mc)
            .ok_or(Error("admin-freshness"))?;
        if age > 128 {
            return Err(Error("admin-freshness"));
        }
        admin_session_id(&self.context.chain, &[0; 32])?;
        Ok(())
    }
}
impl<
        F: FnMut(&ObjectRef, u8) -> Result<Vec<u8>, Error>,
        H: FinalizedAnchorSource,
        S: CurrentRegistry,
    > LifecycleAuthority for NativeLifecycleAuthority<'_, '_, F, H, S>
{
    fn owner(
        &self,
        proof: &OwnerAuth,
        update: &Update,
        identity: &Identity,
    ) -> Result<bool, Error> {
        self.validate_context()?;
        if proof.proof.anchor.seqno >= self.current.coordinate() {
            return Err(Error("owner-finality-coordinate"));
        }
        let anchor = self.context.history.finalized_anchor(proof.proof.anchor.seqno)?;
        let mut reader =
            self.reader.try_borrow_mut().map_err(|_| Error("authority-reader-busy"))?;
        verify_owner_execution(proof, update, identity, &anchor, &self.context.chain, &mut reader)?;
        Ok(true)
    }
    fn possession(
        &self,
        proof: &PossessionAuth,
        update: &Update,
        key: &Key,
    ) -> Result<bool, Error> {
        verify_possession(&self.context.chain, update, key, proof)?;
        Ok(true)
    }
    fn administration(
        &self,
        proof: &IdentityAuth,
        update: &Update,
        identity: &Identity,
        inclusion: u32,
    ) -> Result<bool, Error> {
        self.validate_context()?;
        if inclusion != self.current.coordinate() {
            return Err(Error("authority-current-state"));
        }
        let expected = make_duty(
            &self.context.chain,
            self.context.governing,
            admin_session_id(&self.context.chain, &identity.identity)?,
            5,
            update.nonce,
            &encode(update)?,
        )?;
        let keys = select_identity_keys(identity, self.current, inclusion, &[(5, 1, 1)])?;
        let mut reader =
            self.reader.try_borrow_mut().map_err(|_| Error("authority-reader-busy"))?;
        let certificate = decode::<Certificate>(&reader.resolve(&proof.certificate, 4)?)?;
        verify_identity_certificate(&certificate, &expected, identity, &keys, inclusion)?;
        Ok(true)
    }
}
/// Replays one complete ordered identity-update block. Native elector admission
/// and configuration-contract installation remain separate execution boundaries.
pub fn apply_native_identity_block<
    F: FnMut(&ObjectRef, u8) -> Result<Vec<u8>, Error>,
    H: FinalizedAnchorSource,
>(
    parent: &RegistryState,
    inclusion: u32,
    updates: &[(Update, Authorizations)],
    context: &NativeIdentityContext<'_, H>,
    reader: &mut ObjectReader<F>,
) -> Result<RegistryState, Error> {
    parent.apply_identity_block(inclusion, updates, |current, update, evidence| {
        let authority = NativeLifecycleAuthority::new(current, context, reader);
        authority.validate_context()?;
        let identity =
            current.identities().get(&update.identity).ok_or(Error("unknown-identity"))?;
        apply_identity_update(identity, current, update, evidence, inclusion, &authority)
    })
}
