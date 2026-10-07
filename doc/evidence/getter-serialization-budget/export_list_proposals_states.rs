// Append to tosctl/src/node-control/contracts/tests/config_list_proposals_sandbox.rs
// and run (README.md). It reuses that file's launch/register/many/account_bocs helpers.

/// Writes the genesis configuration contract's code and data BOCs holding the
/// requested proposal sets, for an external measurement of the getter's result.
#[test]
#[ignore]
fn export_list_proposals_states() {
    let out = std::path::PathBuf::from(std::env::var("EXPORT_DIR").expect("EXPORT_DIR"));
    let small_value = build(|c| {
        c.append_u32(7).unwrap();
    });
    let cases: Vec<(String, Vec<Stored>)> = {
        let mut cases = Vec::new();
        for n in [0u32, 1, 2, 61, 62, 63] {
            cases.push((format!("unvoted-{n}"), many(n)));
        }
        for n in [1u32, 61, 62, 63] {
            let set = many(n)
                .into_iter()
                .map(|mut s| {
                    s.value = Some(small_value.clone());
                    s.value_hash = Some([0x33; 32]);
                    s
                })
                .collect();
            cases.push((format!("valued-{n}"), set));
        }
        for n in [1u32, 16, 17, 18] {
            let set = many(n)
                .into_iter()
                .map(|mut s| {
                    s.voters = (0u16..21).collect();
                    s
                })
                .collect();
            cases.push((format!("voters21-{n}"), set));
        }
        cases
    };
    for (name, set) in cases {
        let mut chain = launch();
        register(&mut chain, &set);
        let (code, data) = account_bocs(&chain);
        std::fs::write(out.join("config-code.boc"), &code).unwrap();
        std::fs::write(out.join(format!("config-data-{name}.boc")), &data).unwrap();
    }
}
