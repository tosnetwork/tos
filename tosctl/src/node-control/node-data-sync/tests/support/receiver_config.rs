use anyhow::{Context, Result};
use serde_json::Value;

/// Config::tl serializes ADNL entries from a map. Compare complete entries as a
/// multiset, preserving duplicates and every field; other arrays remain ordered.
pub fn canonicalize_adnl(config: &mut Value) -> Result<()> {
    config
        .get_mut("adnl")
        .and_then(Value::as_array_mut)
        .context("receiver configuration has no ADNL array")?
        .sort_by_cached_key(Value::to_string);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn config() -> Value {
        json!({
            "adnl": [
                {"@type": "engine.adnl", "id": "second", "category": 0},
                {"@type": "engine.adnl", "id": "first", "category": 1}
            ],
            "control": [{"id": "control", "permissions": 15}],
            "out_port": 3278
        })
    }

    #[test]
    fn accepts_only_adnl_reordering() -> Result<()> {
        let mut expected = config();
        let mut actual = config();
        actual["adnl"].as_array_mut().context("ADNL array")?.reverse();
        assert_ne!(actual, expected);
        canonicalize_adnl(&mut expected)?;
        canonicalize_adnl(&mut actual)?;
        assert_eq!(actual, expected);
        Ok(())
    }

    #[test]
    fn retains_identity_category_permissions_and_duplicates() -> Result<()> {
        let mut expected = config();
        canonicalize_adnl(&mut expected)?;
        for pointer in ["/adnl/0/id", "/adnl/0/category", "/control/0/permissions", "/out_port"] {
            let mut changed = config();
            *changed.pointer_mut(pointer).context("fixture field")? = json!(99);
            canonicalize_adnl(&mut changed)?;
            assert_ne!(changed, expected, "hidden change at {pointer}");
        }
        let mut duplicate = config();
        let entry = duplicate["adnl"][0].clone();
        duplicate["adnl"].as_array_mut().context("ADNL array")?.push(entry);
        canonicalize_adnl(&mut duplicate)?;
        assert_ne!(duplicate, expected);
        let mut missing = config();
        missing["adnl"].as_array_mut().context("ADNL array")?.remove(0);
        canonicalize_adnl(&mut missing)?;
        assert_ne!(missing, expected);
        Ok(())
    }

    #[test]
    fn rejects_missing_or_malformed_adnl() {
        for mut config in [json!({}), json!({"adnl": null}), json!({"adnl": {}})] {
            assert!(canonicalize_adnl(&mut config).is_err());
        }
    }
}
