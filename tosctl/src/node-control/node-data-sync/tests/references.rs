#[path = "support/references.rs"]
mod fixture;
use anyhow::Result;
use fixture::{Mode, References};
use node_data_sync::{
    model::FullId,
    references::{ReferencePolicy, canonical_endpoint},
};
fn id() -> FullId {
    FullId {
        workchain: -1,
        shard: i64::MIN,
        seqno: 10,
        root_hash: "12".repeat(32),
        file_hash: "34".repeat(32),
    }
}
#[test]
fn references_require_every_named_source_and_exact_full_ids() -> Result<()> {
    let frontier = id();
    let network = fixture::network(&frontier);
    let refs = References::new(&network, &frontier, Mode::Agree)?;
    let approval = refs.policy.corroborate(&network, &frontier, &"56".repeat(32))?;
    let receipt = approval.receipt()?;
    assert_eq!(receipt.answers.len(), 2);
    receipt.validate(&network, &frontier, &"56".repeat(32))?;
    for (mode, reason) in [
        (Mode::Behind, "behind"),
        (Mode::WrongAnchor, "another anchor"),
        (Mode::DifferentRoot, "disagrees"),
        (Mode::DifferentFile, "disagrees"),
        (Mode::Unavailable, "unavailable"),
        (Mode::Malformed, "unavailable"),
    ] {
        let refs = References::new(&network, &frontier, mode)?;
        let error = match refs.policy.corroborate(&network, &frontier, &"56".repeat(32)) {
            Ok(_) => panic!("uncorroborated frontier accepted"),
            Err(e) => format!("{e:#}"),
        };
        assert!(error.contains(reason), "wrong refusal: {error}");
    }
    let mut incomplete = receipt.clone();
    incomplete.answers.pop();
    assert!(incomplete.validate(&network, &frontier, &"56".repeat(32)).is_err());
    let mut expired = receipt;
    expired.finished_utc -= 31;
    expired.started_utc = expired.finished_utc;
    for a in &mut expired.answers {
        a.observed_utc = expired.finished_utc;
    }
    assert!(expired.ensure_fresh().is_err());
    Ok(())
}
#[test]
fn endpoint_aliases_and_credentials_cannot_bypass_source_identity() -> Result<()> {
    assert_eq!(
        canonical_endpoint("http://127.0.0.1:1234/jsonRPC")?,
        canonical_endpoint("http://127.0.0.1:1234")?
    );
    assert!(
        ReferencePolicy::from_endpoints(&[
            "http://127.0.0.1:1234".to_owned(),
            "http://127.0.0.1:1234/jsonRPC".to_owned()
        ])
        .is_err()
    );
    for value in [
        "https://user:password@example.invalid/jsonRPC",
        "https://example.invalid/jsonRPC?key=secret",
    ] {
        assert!(canonical_endpoint(value).is_err());
    }
    assert!(ReferencePolicy::from_endpoints(&["http://127.0.0.1:1234".to_owned()]).is_err());
    Ok(())
}
