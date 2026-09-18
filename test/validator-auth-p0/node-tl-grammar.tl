// Design copy of the P0 node-TL finality signature set, pinned two-sources against
// the tos_api.tl production insertion by check_production.py. Not a production
// schema and never fed to the TL parser (it would duplicate the tos_api.tl id).
tosNode.signatureSet.validatorAuth final:Bool cc_seqno:int validator_set_hash:int
    native_session_id:int256 slot:int candidate:consensus.CandidateHashData
    certificate:bytes = tosNode.SignatureSet;
