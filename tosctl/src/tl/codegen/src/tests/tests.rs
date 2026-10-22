/*
 * Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
use super::*;

#[test]
fn test_to_snake_case() {
    assert_eq!(to_snake_case("test"), "test");
    assert_eq!(to_snake_case("foo_bar"), "foo_bar");
    assert_eq!(to_snake_case("test_"), "test_");
    assert_eq!(to_snake_case("_test_"), "_test_");
    assert_eq!(to_snake_case("_test"), "_test");
    assert_eq!(to_snake_case("Test"), "test");
    assert_eq!(to_snake_case("TestMsg"), "test_msg");
    assert_eq!(to_snake_case("TestA"), "test_a");
    assert_eq!(to_snake_case("TTest"), "t_test");
}

#[test]
fn grouped_types_keep_wire_kind_and_constructor_id() {
    use parser::{Item, Matched, Type};
    fn declaration(ty: &str) -> parser::Constructor<Type, parser::Field> {
        let text = format!("probe field:{ty} = Probe;");
        let mut items = parser::parse_string(&text).expect("valid grouped declaration");
        let Matched(Item::Constructor(value), _) = items.remove(0) else {
            panic!("expected a constructor")
        };
        value
    }
    for ty in ["tosNode.shardId", "tosNode.ShardId", "(vector tosNode.shardId)"] {
        let plain = declaration(ty);
        for grouped in [format!("({ty})"), format!("(({ty}))")] {
            let wrapped = declaration(&grouped);
            assert_eq!(plain.fields, wrapped.fields, "GROUPED_TYPE_KIND");
            assert_eq!(plain.tl_id, wrapped.tl_id, "GROUPED_TYPE_ID");
        }
    }
    assert_ne!(declaration("tosNode.shardId").fields, declaration("tosNode.ShardId").fields);
    for malformed in ["probe field:(tosNode.shardId = Probe;", "probe field:() = Probe;"] {
        assert!(parser::parse_string(malformed).is_err(), "GROUPED_MALFORMED");
    }
}
