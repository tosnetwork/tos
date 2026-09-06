//! Public nanotomi equations; these do not authenticate settlement sources.
use orchard::bundle::Flags;

// Logical variants, not wire discriminants. Irrelevant fields are unrepresentable.
#[derive(Debug, Clone, Copy)]
pub enum PublicContext {
    Transfer { fee: u128 },
    Unshield { amount: u128, fee: u128 },
    ShieldClaim { amount: u128 },
    WithdrawalRefund { amount: u128 },
    Genesis { amount: u128 },
    PrivateFeeDistribution { amount: u128 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContextError {
    ZeroPrincipal,
    AmountOverflow,
    BalanceRange,
    ValueBalance,
    Permissions,
}

pub(crate) fn check_context(
    context: PublicContext,
    value_balance: i64,
    flags: &Flags,
) -> Result<(), ContextError> {
    let (magnitude, spends) = match context {
        PublicContext::Transfer { fee } => (fee, true),
        PublicContext::Unshield { amount, fee } => {
            if amount == 0 {
                return Err(ContextError::ZeroPrincipal);
            }
            (amount.checked_add(fee).ok_or(ContextError::AmountOverflow)?, true)
        }
        PublicContext::ShieldClaim { amount }
        | PublicContext::WithdrawalRefund { amount }
        | PublicContext::Genesis { amount }
        | PublicContext::PrivateFeeDistribution { amount } => {
            if amount == 0 {
                return Err(ContextError::ZeroPrincipal);
            }
            (amount, false)
        }
    };
    let magnitude = i64::try_from(magnitude).map_err(|_| ContextError::BalanceRange)?;
    let expected = if spends {
        magnitude
    } else {
        magnitude.checked_neg().ok_or(ContextError::BalanceRange)?
    };
    if value_balance != expected {
        return Err(ContextError::ValueBalance);
    }
    if flags.spends_enabled() != spends || !flags.outputs_enabled() {
        return Err(ContextError::Permissions);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use orchard::bundle::BundleVersion;

    #[test]
    fn shared_cross_language_vectors() {
        let corpus = include_str!("../../testdata/public-context-v1.txt");
        let mut count = 0usize;
        for line in corpus.lines() {
            let fields: Vec<_> = line.split_whitespace().collect();
            assert_eq!(fields.len(), 10, "{line}");
            let word = |index: usize| fields[index].parse::<u64>().expect("u64 fixture word");
            let amount = (u128::from(word(2)) << 64) | u128::from(word(3));
            let fee = (u128::from(word(4)) << 64) | u128::from(word(5));
            let context = match fields[1] {
                "Transfer" => {
                    assert_eq!(amount, 0);
                    PublicContext::Transfer { fee }
                }
                "Unshield" => PublicContext::Unshield { amount, fee },
                kind => {
                    assert_eq!(fee, 0);
                    match kind {
                        "ShieldClaim" => PublicContext::ShieldClaim { amount },
                        "WithdrawalRefund" => PublicContext::WithdrawalRefund { amount },
                        "Genesis" => PublicContext::Genesis { amount },
                        "PrivateFeeDistribution" => {
                            PublicContext::PrivateFeeDistribution { amount }
                        }
                        _ => panic!("unknown fixture context"),
                    }
                }
            };
            let bit = |index: usize| match fields[index] {
                "0" => false,
                "1" => true,
                _ => panic!("invalid fixture bit"),
            };
            let flags = Flags::from_byte(
                u8::from(bit(7)) | (u8::from(bit(8)) << 1),
                BundleVersion::orchard_v2(),
            )
            .expect("fixture flags");
            let balance = fields[6].parse::<i64>().expect("i64 fixture balance");
            assert_eq!(check_context(context, balance, &flags).is_ok(), bit(9), "{}", fields[0]);
            count = count.checked_add(1).expect("fixture count");
        }
        assert_eq!(count, 31);
    }

    #[test]
    fn public_context_requires_value_and_permissions() {
        let contexts = [
            (PublicContext::Transfer { fee: 100 }, 100, true),
            (PublicContext::Unshield { amount: 80, fee: 20 }, 100, true),
            (PublicContext::ShieldClaim { amount: 5000 }, -5000, false),
            (PublicContext::WithdrawalRefund { amount: 5000 }, -5000, false),
            (PublicContext::Genesis { amount: 5000 }, -5000, false),
            (PublicContext::PrivateFeeDistribution { amount: 5000 }, -5000, false),
        ];
        for (context, balance, spends) in contexts {
            for bits in 0..=3 {
                let flags = Flags::from_byte(bits, BundleVersion::orchard_v2()).expect("flags");
                let expected = if bits == (if spends { 3 } else { 2 }) {
                    Ok(())
                } else {
                    Err(ContextError::Permissions)
                };
                assert_eq!(check_context(context, balance, &flags), expected);
            }
            let flags = Flags::from_byte(if spends { 3 } else { 2 }, BundleVersion::orchard_v2())
                .expect("flags");
            for wrong_balance in [0, -balance, balance.checked_add(1).expect("fixture value")] {
                assert_eq!(
                    check_context(context, wrong_balance, &flags),
                    Err(ContextError::ValueBalance)
                );
            }
        }
    }

    #[test]
    fn public_context_uses_checked_wide_amounts() {
        let spending = BundleVersion::orchard_v2().default_flags();
        let output = Flags::SPENDS_DISABLED;
        assert_eq!(
            check_context(PublicContext::Transfer { fee: i64::MAX as u128 }, i64::MAX, &spending),
            Ok(())
        );
        assert_eq!(
            check_context(PublicContext::Genesis { amount: i64::MAX as u128 }, -i64::MAX, &output),
            Ok(())
        );
        assert_eq!(check_context(PublicContext::Transfer { fee: 0 }, 0, &spending), Ok(()));
        assert_eq!(check_context(PublicContext::Genesis { amount: 0 }, 0, &output), Err(ContextError::ZeroPrincipal));
        assert_eq!(
            check_context(PublicContext::Unshield { amount: u128::MAX, fee: 1 }, 0, &spending),
            Err(ContextError::AmountOverflow)
        );
        assert_eq!(
            check_context(
                PublicContext::Transfer {
                    fee: (i64::MAX as u128).checked_add(1).expect("fixture amount")
                },
                i64::MIN,
                &spending
            ),
            Err(ContextError::BalanceRange)
        );
        assert_eq!(
            check_context(
                PublicContext::Genesis {
                    amount: (i64::MAX as u128).checked_add(2).expect("fixture amount")
                },
                i64::MAX,
                &output
            ),
            Err(ContextError::BalanceRange)
        );
    }
}
