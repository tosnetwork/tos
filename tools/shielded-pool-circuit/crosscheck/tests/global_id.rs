#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
//! GLOBALID must survive fee and size-limit context rebuilds.
use chain_block::{Cell, MsgAddressInt, Serializable, StateInit};
use tos_sandbox::{compile_func_with_stdlib, Blockchain, MessageBuilder};

#[test]
fn network_identity_reaches_transactions_getters_and_rebuilt_contexts() {
    let dir = tempfile::tempdir().expect("source directory");
    let source = dir.path().join("identity.fc");
    std::fs::write(
        &source,
        r#"
int network_id() asm "GLOBALID";
int get_identity() method_id { return network_id(); }
int get_stored() method_id { return get_data().begin_parse().preload_int(32); }
() recv_internal(cell message, slice body) impure {
  set_data(begin_cell().store_int(network_id(), 32).end_cell());
}
"#,
    )
    .expect("identity source");
    let code = compile_func_with_stdlib(&[source]).expect("identity probe");
    let mut bc = Blockchain::with_global_version_and_base_workchain(16).expect("chain");
    bc.set_workchain(0);
    let mut config = bc.config_params().clone();
    config
        .set_config(chain_block::ConfigParamEnum::ConfigParam31(
            chain_block::ConfigParam31::default(),
        ))
        .expect("complete test configuration");
    config.set_config(chain_block::ConfigParamEnum::ConfigParam19(2)).expect("network identity");
    bc.set_config(config).expect("network context");
    let payer = bc.treasury("identity-probe", 100_000_000_000).expect("payer");
    let init = StateInit::with_code_and_data(code, Cell::default());
    let address = MsgAddressInt::with_params(
        0,
        init.write_to_new_cell().unwrap().into_cell().unwrap().hash(0),
    )
    .unwrap();
    bc.send_message(
        MessageBuilder::internal(payer.address(), &address, 1_000_000_000)
            .state_init(init)
            .bounce(false)
            .build(),
    )
    .unwrap()
    .expect_success();
    for expected in [2_i32, -239] {
        let mut config = bc.config_params().clone();
        config
            .set_config(chain_block::ConfigParamEnum::ConfigParam19(u32::from_be_bytes(
                expected.to_be_bytes(),
            )))
            .expect("selected identity");
        bc.set_config(config).expect("network context");
        for rebuild in 0..3 {
            if rebuild == 1 {
                bc.set_config(bc.config_params().clone()).expect("fee update");
            }
            if rebuild == 2 {
                bc.set_size_limits_config(bc.config_params().size_limits_config().unwrap())
                    .expect("limit update");
            }
            let read =
                bc.run_get_method(&address, "get_identity", vec![]).expect("GLOBALID getter");
            read.expect_success();
            assert_eq!(read.int_at(0), i128::from(expected));
            bc.send_message(
                MessageBuilder::internal(payer.address(), &address, 1_000_000_000)
                    .bounce(false)
                    .build(),
            )
            .expect("identity transaction")
            .expect_success();
            let stored =
                bc.run_get_method(&address, "get_stored", vec![]).expect("transaction identity");
            stored.expect_success();
            assert_eq!(stored.int_at(0), i128::from(expected));
        }
    }
}
