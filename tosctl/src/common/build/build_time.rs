/*
 * Copyright (C) 2026 TOS Blockchain Teams.
 *
 * Licensed under the Apache License, Version 2.0.
 * See the common/LICENSE file in this repository.
 */
//! The build timestamp shared by the workspace's build scripts, each of which includes this
//! file with `#[path]`.
use std::process::Command;

/// Build timestamp taken from the source, never from the wall clock, so that
/// two builds of one commit embed the same value: SOURCE_DATE_EPOCH when set,
/// otherwise the commit date of HEAD. Formatted in UTC so the host time zone
/// does not leak into the binary.
pub fn build_time() -> Result<String, String> {
    println!("cargo:rerun-if-env-changed=SOURCE_DATE_EPOCH");
    let epoch = match std::env::var("SOURCE_DATE_EPOCH") {
        Ok(value) if !value.trim().is_empty() => value,
        Ok(_) | Err(std::env::VarError::NotPresent) => {
            match Command::new("git").args(["log", "-1", "--format=%ct"]).output() {
                Ok(out) if out.status.success() => String::from_utf8(out.stdout)
                    .map_err(|e| format!("commit date is not UTF-8: {e}"))?,
                _ => return Ok("Unknown".to_string()),
            }
        }
        Err(e) => return Err(format!("SOURCE_DATE_EPOCH is unreadable: {e}")),
    };
    let epoch: i64 = epoch
        .trim()
        .parse()
        .map_err(|e| format!("build epoch {:?} is not a Unix timestamp: {e}", epoch.trim()))?;
    format_utc(epoch).ok_or_else(|| format!("build epoch {epoch} is outside the supported range"))
}

/// `epoch` as `YYYY-MM-DD HH:MM:SS +0000`, computed here rather than by `date(1)`, whose
/// options differ between GNU and BSD hosts. Days are converted to a civil date in the
/// proleptic Gregorian calendar; `None` for a year that does not have four digits.
fn format_utc(epoch: i64) -> Option<String> {
    let days = epoch.div_euclid(86_400);
    let secs = epoch.rem_euclid(86_400);
    let (hour, minute, second) = (secs / 3_600, secs % 3_600 / 60, secs % 60);
    // Shift the epoch to 0000-03-01, so that each 400-year era starts on a March 1 and the
    // leap day is the last day of its year.
    let z = days.checked_add(719_468)?;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe =
        doe.checked_sub(doe / 1_460)?.checked_add(doe / 36_524)?.checked_sub(doe / 146_096)? / 365;
    let doy =
        doe.checked_sub(yoe.checked_mul(365)?.checked_add(yoe / 4)?.checked_sub(yoe / 100)?)?;
    let mp = doy.checked_mul(5)?.checked_add(2)? / 153;
    let day = doy.checked_sub(mp.checked_mul(153)?.checked_add(2)? / 5)?.checked_add(1)?;
    let month = if mp < 10 { mp.checked_add(3)? } else { mp.checked_sub(9)? };
    let year = era.checked_mul(400)?.checked_add(yoe)?.checked_add(i64::from(month <= 2))?;
    if !(0..=9_999).contains(&year) {
        return None;
    }
    Some(format!("{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02} +0000"))
}
