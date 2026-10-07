// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only

fn changed(cell: &Cell, offset: usize, bits: usize, value: u64) -> Cell {
    let mut data = cell.data().to_vec();
    for bit in 0..bits {
        let at = offset + bit;
        let mask = 1 << (7 - at % 8);
        data[at / 8] = (data[at / 8] & !mask) | (((value >> (bits - bit - 1)) as u8 & 1) * mask);
    }
    let mut builder = BuilderData::with_raw(data, cell.bit_length()).unwrap();
    builder.checked_append_reference(cell.reference(0).unwrap()).unwrap();
    builder.into_cell().unwrap()
}

#[test]
fn cached_fee_decode_is_canonical_and_bounded() {
    let original = FeeIntent::new(binding(), payload(), 1_780_000_000).unwrap();
    let epoch = binding().epoch0;
    for class in [FeeClass::RescueAuth, FeeClass::Pop, FeeClass::Prepare] {
        let p = FeePayload::from_submission(class, submission(class, AuthRole::Rescue)).unwrap();
        let intent = FeeIntent::new(binding(), p, 1_780_000_000).unwrap();
        let decoded = FeeIntent::from_cached_cell(intent.cell().clone(), epoch).unwrap();
        assert_eq!(decoded.digest(), intent.digest());
        assert_eq!(decoded.leaf(), intent.leaf());
        assert_eq!(
            decoded.encode_external(&signature()).unwrap(),
            intent.encode_external(&signature()).unwrap()
        );
    }
    for (offset, bits, value) in [(0, 32, 0), (32, 8, 0), (168, 8, 0), (176, 11, 1025)] {
        assert!(
            FeeIntent::from_cached_cell(changed(original.cell(), offset, bits, value), epoch)
                .is_err()
        );
    }
    assert!(
        FeeIntent::from_cached_cell(
            changed(original.cell(), 699, 32, u64::from(LEAF_COUNT)),
            epoch
        )
        .is_err(),
        "cached parser accepted exhausted leaf"
    );
    let mut zero = binding();
    zero.value = 0;
    assert!(
        FeeIntent::from_cached_cell(FeeIntent::encode(zero, payload()).unwrap().cell, epoch)
            .is_err(),
        "cached parser accepted zero value"
    );
    let mut extra = BuilderData::from_cell(original.cell()).unwrap();
    extra.append_bit_one().unwrap();
    assert!(FeeIntent::from_cached_cell(extra.into_cell().unwrap(), epoch).is_err());
    let mut extra = BuilderData::from_cell(original.cell()).unwrap();
    extra.checked_append_reference(Cell::default()).unwrap();
    assert!(FeeIntent::from_cached_cell(extra.into_cell().unwrap(), epoch).is_err());
    // VarUInteger16 permits a wider serialized form; pending intents must use
    // the same shortest representation as the signing encoder.
    let mut source = SliceData::load_cell(original.cell().clone()).unwrap();
    let prefix = source.get_next_bits(763).unwrap();
    let length = source.get_next_int(4).unwrap() as usize;
    let amount = source.get_next_bits(length * 8).unwrap();
    let mut long = BuilderData::new();
    long.append_raw(&prefix, 763).unwrap();
    long.append_bits(length + 1, 4).unwrap();
    long.append_u8(0).unwrap();
    long.append_raw(&amount, length * 8).unwrap();
    long.checked_append_reference(source.checked_drain_reference().unwrap()).unwrap();
    assert!(
        FeeIntent::from_cached_cell(long.into_cell().unwrap(), epoch).is_err(),
        "cached parser accepted noncanonical amount"
    );
}
