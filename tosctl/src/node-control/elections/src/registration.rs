//! Retain transport registration through actual, possibly postponed duties.
use crate::providers::ValidatorConfig;
use anyhow::{Context, ensure};
use chain_block::{ConfigParam15, ValidatorSet};

pub(crate) const RETENTION_LAG: u64 = 300;

pub fn pending_until(election_id: u64, now: u64, cfg: &ConfigParam15) -> anyhow::Result<u64> {
    let earliest_start = now
        .checked_add(u64::from(cfg.elections_end_before))
        .context("registration start overflow")?;
    let until = election_id
        .max(earliest_start)
        .checked_add(u64::from(cfg.validators_elected_for))
        .and_then(|value| value.checked_add(RETENTION_LAG))
        .context("registration expiry overflow")?;
    ensure!(
        i32::try_from(election_id).is_ok() && i32::try_from(until).is_ok(),
        "registration time exceeds control protocol"
    );
    Ok(until)
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Renewal {
    pub election_id: u64,
    pub key_id: Vec<u8>,
    pub adnl: Vec<u8>,
    pub until: u64,
}

pub(crate) fn duty_renewals(
    config: &ValidatorConfig,
    current: Option<&ValidatorSet>,
    next: Option<&ValidatorSet>,
    now: u64,
) -> anyhow::Result<Vec<Renewal>> {
    ensure!(config.keys.len() <= 128, "too many validator registrations");
    let mut result = Vec::new();
    for (&election_id, entry) in &config.keys {
        ensure!(entry.adnl_addrs.len() <= 16, "too many registered addresses");
        let mut duties = Vec::new();
        let mut until = entry.expired_at;
        for (adnl, expires) in &entry.adnl_addrs {
            let end = [current, next]
                .into_iter()
                .flatten()
                .filter(|set| {
                    set.list().iter().any(|v| {
                        v.adnl_addr
                            .as_ref()
                            .is_some_and(|addr| addr.as_slice().as_slice() == adnl.as_slice())
                    })
                })
                .map(|set| u64::from(set.utime_until()))
                .max();
            if let Some(end) = end {
                let duty_until =
                    end.max(now).checked_add(RETENTION_LAG).context("duty expiry overflow")?;
                until = until.max(duty_until).max(*expires);
                duties.push((adnl, *expires));
            }
        }
        ensure!(
            i32::try_from(election_id).is_ok() && i32::try_from(until).is_ok(),
            "registration time exceeds control protocol"
        );
        for (adnl, expires) in duties {
            if entry.expired_at < until || expires < until {
                ensure!(entry.key_id.len() == 32 && adnl.len() == 32, "registration key width");
                result.push(Renewal {
                    election_id,
                    key_id: entry.key_id.clone(),
                    adnl: adnl.clone(),
                    until,
                });
            }
        }
    }
    Ok(result)
}

/// Reflect a completed native-console write before another action reuses the snapshot.
pub(crate) fn mark_retained(config: &mut ValidatorConfig, plan: &Renewal) -> anyhow::Result<()> {
    let entry =
        config.keys.get_mut(&plan.election_id).context("retained election record disappeared")?;
    ensure!(entry.key_id == plan.key_id, "retained election key changed");
    let address = entry
        .adnl_addrs
        .iter_mut()
        .find(|(adnl, _)| adnl == &plan.adnl)
        .context("retained election address disappeared")?;
    entry.expired_at = entry.expired_at.max(plan.until);
    address.1 = address.1.max(plan.until);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::ValidatorEntry;
    use chain_block::{SigPubKey, UInt256, ValidatorDescr};

    fn config() -> ValidatorConfig {
        let mut config = ValidatorConfig::new();
        config.keys.insert(
            100,
            ValidatorEntry {
                key_id: vec![1; 32],
                public_key: vec![],
                adnl_addrs: vec![(vec![2; 32], 200)],
                expired_at: 200,
            },
        );
        config
    }
    fn set(until: u32, adnl: u8) -> ValidatorSet {
        ValidatorSet::new(
            100,
            until,
            1,
            vec![ValidatorDescr::with_params(
                SigPubKey::from_bytes(&[3; 32]).unwrap(),
                1,
                Some(UInt256::from([adnl; 32])),
            )],
        )
        .unwrap()
    }
    #[test]
    fn late_election_covers_close_margin_and_full_term() {
        let cfg = ConfigParam15 {
            validators_elected_for: 7200,
            elections_start_before: 3600,
            elections_end_before: 900,
            stake_held_for: 3600,
        };
        assert_eq!(pending_until(100, 20000, &cfg).unwrap(), 28400);
        assert_eq!(pending_until(30000, 20000, &cfg).unwrap(), 37500);
        assert!(pending_until(100, u64::MAX, &cfg).unwrap_err().to_string().contains("overflow"));
        assert!(
            pending_until(i32::MAX as u64, 100, &cfg).unwrap_err().to_string().contains("protocol")
        );
    }
    #[test]
    fn announced_term_extends_original_election_without_new_identity() {
        let cfg = config();
        let next = set(20000, 2);
        let plan = duty_renewals(&cfg, None, Some(&next), 1000).unwrap();
        assert_eq!(
            plan,
            vec![Renewal {
                election_id: 100,
                key_id: vec![1; 32],
                adnl: vec![2; 32],
                until: 20300
            }]
        );
    }
    #[test]
    fn installed_expired_set_is_retained_during_another_delay() {
        let cfg = config();
        let current = set(200, 2);
        assert_eq!(duty_renewals(&cfg, Some(&current), None, 5000).unwrap()[0].until, 5300);
    }
    #[test]
    fn unrelated_and_already_retained_addresses_do_not_write() {
        let mut cfg = config();
        let unrelated = set(20000, 9);
        assert!(duty_renewals(&cfg, Some(&unrelated), None, 1000).unwrap().is_empty());
        let own = set(20000, 2);
        let entry = cfg.keys.get_mut(&100).unwrap();
        entry.expired_at = 30000;
        entry.adnl_addrs[0].1 = 30000;
        assert!(duty_renewals(&cfg, Some(&own), None, 1000).unwrap().is_empty());
    }
    #[test]
    fn address_repair_never_shortens_permanent_expiry() {
        let mut cfg = config();
        cfg.keys.get_mut(&100).unwrap().expired_at = 30000;
        assert_eq!(duty_renewals(&cfg, None, Some(&set(20000, 2)), 1000).unwrap()[0].until, 30000);
    }
    #[test]
    fn malformed_and_excessive_registration_inputs_refuse() {
        let mut cfg = config();
        cfg.keys.get_mut(&100).unwrap().key_id.clear();
        assert!(
            duty_renewals(&cfg, None, Some(&set(20000, 2)), 1000)
                .unwrap_err()
                .to_string()
                .contains("width")
        );
        let mut cfg = config();
        let entry = cfg.keys[&100].clone();
        for n in 1000..1128 {
            cfg.keys.insert(n, entry.clone());
        }
        assert!(
            duty_renewals(&cfg, None, None, 1000).unwrap_err().to_string().contains("too many")
        );
    }
    #[test]
    fn multiple_duty_addresses_share_the_longest_permanent_deadline() {
        let mut cfg = config();
        cfg.keys.get_mut(&100).unwrap().adnl_addrs.push((vec![4; 32], 200));
        for (current, next) in [(2, 4), (4, 2)] {
            let plans =
                duty_renewals(&cfg, Some(&set(10000, current)), Some(&set(20000, next)), 1000)
                    .unwrap();
            assert_eq!(plans.len(), 2);
            assert!(plans.iter().all(|plan| plan.until == 20300));
        }
    }
}
