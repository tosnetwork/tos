/*
 * Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */

/// Convert nanotos to a decimal string.
pub fn nanotos_to_dec_string(value: u64) -> String {
    value.to_string()
}

/// Convert a floating-point TOS amount to nanotos.
pub fn tos_to_nanotos(tos: f64) -> u64 {
    (tos * 1_000_000_000.0).round() as u64
}

/// Convert nanotos to a floating-point TOS amount.
pub fn nanotos_to_tos(nanotos: u64) -> f64 {
    nanotos as f64 / 1_000_000_000.0
}

/// Format nanotos as a human-readable TOS string (up to 4 decimal places, trailing zeros removed).
pub fn display_tos(nanotos: u64) -> String {
    format!("{:.4}", nanotos_to_tos(nanotos))
        .trim_end_matches('0')
        .trim_end_matches('.')
        .to_string()
}

/// Parse a nanotos decimal string and format as TOS (4 decimal places).
/// Returns the original string if it cannot be parsed.
pub fn display_tos_from_str(nanotos_str: &str) -> String {
    nanotos_str
        .trim()
        .parse::<u64>()
        .map(display_tos)
        .unwrap_or_else(|_| nanotos_str.to_string())
}

// ─── Backward-compatible aliases ───────────────────────��─────────────────

#[doc(hidden)]
pub use nanotos_to_dec_string as nanotons_to_dec_string;
#[doc(hidden)]
pub use tos_to_nanotos as tons_f64_to_nanotons;
#[doc(hidden)]
pub use nanotos_to_tos as nanotons_to_tons_f64;
#[doc(hidden)]
pub use display_tos as display_tons;
#[doc(hidden)]
pub use display_tos as display_coins;
#[doc(hidden)]
pub use display_tos_from_str as display_tons_from_str;
#[doc(hidden)]
pub use display_tos_from_str as display_coins_from_str;
#[doc(hidden)]
pub use nanotos_to_dec_string as nanocoins_to_dec_string;
#[doc(hidden)]
pub use tos_to_nanotos as coins_to_nanocoins;
#[doc(hidden)]
pub use nanotos_to_tos as nanocoins_to_coins;

#[cfg(test)]
mod tests {
    use super::display_tos;
    #[test]
    fn test_display_tos() {
        assert_eq!(display_tos(0_100_000_000), "0.1");
        assert_eq!(display_tos(1_000_000_000), "1");
        assert_eq!(display_tos(1_100_000_000), "1.1");
        assert_eq!(display_tos(1_100_100_000), "1.1001");
        assert_eq!(display_tos(1_100_010_000), "1.1");
        assert_eq!(display_tos(123_000_000_000), "123");
        assert_eq!(display_tos(123_450_000_000), "123.45");
        assert_eq!(display_tos(123_000_100_000), "123.0001");
        assert_eq!(display_tos(123_000_180_000), "123.0002");
    }
}
