//! Every independently deployable legacy wallet refuses a forged weak authority.
use chain_block::{
    BuilderData, Cell, IBitstring, MsgAddressInt, Serializable, SliceData, StateInit,
};
use ed25519_dalek::{Signer, SigningKey};
use tos_sandbox::{Blockchain, MessageBuilder, compile_func_with_stdlib};
mod weak_ed25519;
const TOS: u64 = 1_000_000_000;
const ID: u32 = 42;
fn cell(f: impl FnOnce(&mut BuilderData)) -> Cell {
    let mut b = BuilderData::new();
    f(&mut b);
    b.into_cell().unwrap()
}
fn source(name: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../../crypto/smartcont").join(name)
}
fn data(name: &str, key: &[u8; 32]) -> Cell {
    cell(|b| {
        if name == "wallet-v5-code.fc" {
            b.append_bit_one().unwrap();
        }
        if name == "highload-wallet-v3-code.fc" {
            b.append_u256(key).unwrap();
            b.append_u32(ID).unwrap();
            b.append_bit_zero().unwrap();
            b.append_bit_zero().unwrap();
            b.append_u64(0).unwrap();
            b.append_bits(3600, 22).unwrap();
            return;
        }
        if name == "highload-wallet-v2-code.fc" {
            b.append_u32(ID).unwrap();
            b.append_u64(0).unwrap();
        } else {
            b.append_u32(1).unwrap();
            if matches!(
                name,
                "wallet3-code.fc"
                    | "wallet-v4-code.fc"
                    | "wallet-v5-code.fc"
                    | "highload-wallet-code.fc"
                    | "restricted-wallet3-code.fc"
            ) {
                b.append_u32(ID).unwrap();
            }
        }
        b.append_u256(key).unwrap();
        if matches!(name, "wallet-v4-code.fc" | "wallet-v5-code.fc" | "highload-wallet-v2-code.fc")
        {
            b.append_bit_zero().unwrap();
        }
        if matches!(name, "restricted-wallet2-code.fc" | "restricted-wallet3-code.fc") {
            b.append_u32(1).unwrap();
            b.append_bit_zero().unwrap();
        }
    })
}
fn signed_body(name: &str, now: u32, address: &MsgAddressInt) -> Cell {
    cell(|b| {
        if name == "wallet-v5-code.fc" {
            b.append_u32(0x7369676e).unwrap();
        }
        b.append_i32(42).unwrap();
        if matches!(name, "simple-wallet-code.fc" | "simple-wallet-ext-code.fc") {
            b.append_u32(1).unwrap();
            return;
        }
        if name == "highload-wallet-v3-code.fc" {
            address.write_to(b).unwrap();
            b.append_u32(ID).unwrap();
            b.checked_append_reference(cell(|b| {
                b.append_bits(0x18, 6).unwrap(); // int message, addr_none source
                address.write_to(b).unwrap();
                b.append_bits(0, 4 + 1 + 4 + 4).unwrap(); // zero coins/currencies/fees
                b.append_u64(0).unwrap();
                b.append_u32(0).unwrap();
                b.append_bit_zero().unwrap();
                b.append_bit_zero().unwrap();
            }))
            .unwrap();
            b.append_u8(3).unwrap();
            b.append_bits(1, 23).unwrap();
            b.append_u64(u64::from(now)).unwrap();
            b.append_bits(3600, 22).unwrap();
            return;
        }
        if name == "highload-wallet-v2-code.fc" {
            b.append_u32(ID).unwrap();
            b.append_u64((u64::from(now) + 100) << 32).unwrap();
            b.append_bit_zero().unwrap();
            return;
        }
        let subwallet = matches!(
            name,
            "wallet3-code.fc"
                | "wallet-v4-code.fc"
                | "wallet-v5-code.fc"
                | "highload-wallet-code.fc"
                | "restricted-wallet3-code.fc"
        );
        if subwallet {
            b.append_u32(ID).unwrap();
        }
        if subwallet {
            b.append_u32(now + 100).unwrap();
            b.append_u32(1).unwrap();
        } else {
            b.append_u32(1).unwrap();
            b.append_u32(now + 100).unwrap();
        }
        if name == "wallet-v4-code.fc" {
            b.append_u8(0).unwrap();
        }
        if name == "highload-wallet-code.fc" {
            b.append_bit_zero().unwrap();
        }
        if name == "wallet-v5-code.fc" {
            b.append_bit_zero().unwrap();
            b.append_bit_zero().unwrap();
        }
    })
}
fn packet(name: &str, body: &Cell, signature: &[u8; 64]) -> Cell {
    cell(|b| {
        if name == "highload-wallet-v3-code.fc" {
            b.checked_append_reference(body.clone()).unwrap();
            b.append_raw(signature, 512).unwrap();
            return;
        }
        let suffix = name == "wallet-v5-code.fc";
        if !suffix {
            b.append_raw(signature, 512).unwrap();
        }
        b.append_builder(&SliceData::load_cell(body.clone()).unwrap().as_builder().unwrap())
            .unwrap();
        if suffix {
            b.append_raw(signature, 512).unwrap();
        }
    })
}
fn deploy(name: &str, key: &[u8; 32], code: Cell) -> (Blockchain, MsgAddressInt) {
    let mut bc = Blockchain::with_global_version_and_base_workchain(14).unwrap();
    let mut config = bc.config_params().clone();
    config
        .set_config(chain_block::ConfigParamEnum::ConfigParam1(chain_block::ConfigParam1 {
            elector_addr: chain_block::UInt256::default().into(),
        }))
        .unwrap();
    config
        .set_config(chain_block::ConfigParamEnum::ConfigParam31(chain_block::ConfigParam31 {
            fundamental_smc_addr: chain_block::FundamentalSmcAddresses::default(),
        }))
        .unwrap();
    bc.set_config(config).unwrap();
    let init = StateInit::with_code_and_data(code, data(name, key));
    let hash = init.write_to_new_cell().unwrap().into_cell().unwrap().hash(0);
    let address = MsgAddressInt::with_params(0, hash).unwrap();
    let funder = bc.treasury("funder", 1000 * TOS).unwrap();
    bc.send_message(
        MessageBuilder::internal(funder.address(), &address, 100 * TOS)
            .bounce(false)
            .state_init(init)
            .build(),
    )
    .unwrap()
    .expect_success();
    (bc, address)
}
#[test]
fn twelve_wallet_families_refuse_forged_keys_with_strong_key_positive_controls() {
    for name in [
        "simple-wallet-code.fc",
        "simple-wallet-ext-code.fc",
        "wallet-code.fc",
        "wallet3-code.fc",
        "wallet-v4-code.fc",
        "wallet-v5-code.fc",
        "highload-wallet-code.fc",
        "highload-wallet-v2-code.fc",
        "highload-wallet-v3-code.fc",
        "restricted-wallet-code.fc",
        "restricted-wallet2-code.fc",
        "restricted-wallet3-code.fc",
    ] {
        println!("wallet family: {name}");
        let code = compile_func_with_stdlib(&[source(name)]).expect(name);
        let strong = SigningKey::from_bytes(&[0x42; 32]);
        let (mut bc, address) = deploy(name, &strong.verifying_key().to_bytes(), code.clone());
        let body = signed_body(name, bc.now(), &address);
        let signature = strong.sign(body.hash(0).as_slice()).to_bytes();
        let msg = MessageBuilder::external(&address)
            .body_slice(SliceData::load_cell(packet(name, &body, &signature)).unwrap())
            .build();
        let result = bc.send_message(msg).expect(name);
        result.expect_success();
        // The identity with its sign bit set admits a forgery for every message.
        let weak = weak_ed25519::weak_keys()[12];
        let (mut bc, address) = deploy(name, &weak, code);
        let body = signed_body(name, bc.now(), &address);
        let signature = weak_ed25519::forge(&weak, body.hash(0).as_slice())
            .expect("forge sign-bit alias authority");
        let message = MessageBuilder::external(&address)
            .body_slice(SliceData::load_cell(packet(name, &body, &signature)).unwrap())
            .build();
        let error = match bc.send_message(message) {
            Ok(_) => panic!("{name}: forged authority accepted"),
            Err(error) => error.to_string(),
        };
        let expected = match name {
            "wallet-v5-code.fc" => 135,
            "highload-wallet-v3-code.fc" => 33,
            "restricted-wallet3-code.fc" => 36,
            "wallet-code.fc"
            | "restricted-wallet-code.fc"
            | "restricted-wallet2-code.fc"
            | "simple-wallet-code.fc"
            | "simple-wallet-ext-code.fc" => 34,
            _ => 35,
        };
        assert!(error.contains(&format!("{expected}")), "{name}: {error}");
    }
}
