//! Current-network fixtures follow Genesis, independently of the VM capability ceiling.

pub fn global_version() -> u32 {
    let source = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../../crypto/smartcont/gen-zerostate.fif"
    ));
    configured_version(source, chain_block::SUPPORTED_VERSION)
}

fn configured_version(source: &str, supported_version: u32) -> u32 {
    let mut declarations = source.lines().filter_map(|line| {
        let line = line.trim();
        if line.starts_with("//") {
            return None;
        }
        line.strip_suffix(" config.version!")
    });
    let declaration = declarations.next().expect("Genesis must declare its global version");
    assert!(declarations.next().is_none(), "Genesis global version must be unambiguous");
    let version = declaration
        .split_whitespace()
        .next()
        .expect("Genesis version value")
        .parse::<u32>()
        .expect("Genesis version must be an explicit integer");
    assert!(version <= supported_version, "the VM must support Genesis");
    version
}

#[cfg(test)]
mod tests {
    use super::configured_version;

    #[test]
    fn a_higher_vm_ceiling_does_not_change_the_configured_version() {
        let source = "16 capCreateStats config.version!";
        assert_eq!(configured_version(source, 16), 16);
        assert_eq!(configured_version(source, 19), 16);
        assert_eq!(configured_version("15 capCreateStats config.version!", 16), 15);
    }
}
