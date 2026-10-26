/*
 * Copyright (C) 2025-2026 TOS Blockchain Teams.
 * Licensed under the GNU General Public License v3.0.
 */

//! Integration tests for the TOS Sandbox.

#[cfg(test)]
mod tests {
    use crate::blockchain::Blockchain;
    use crate::message_builder::MessageBuilder;

    // ─── Test 1: Treasury creation + balance check ─────────────────────

    #[test]
    fn test_treasury_creation() {
        let mut bc = Blockchain::new().expect("Failed to create blockchain");

        let balance = 1_000_000_000_000u64; // 1000 TOS
        let treasury = bc.treasury("deployer", balance).expect("Failed to create treasury");

        // Treasury should have an address
        let addr = treasury.address();
        assert!(!addr.to_string().is_empty(), "Treasury address should not be empty");

        // Account should exist in the blockchain
        let account = bc.get_account(addr).expect("Treasury account should exist");
        assert!(account.is_none() == false, "Treasury account should not be None");

        // Treasury name should match
        assert_eq!(treasury.name(), "deployer");
    }

    #[test]
    fn test_multiple_treasuries_different_addresses() {
        let mut bc = Blockchain::new().expect("Failed to create blockchain");

        let t1 = bc.treasury("alice", 1_000_000_000).expect("alice");
        let t2 = bc.treasury("bob", 2_000_000_000).expect("bob");

        // Different names should produce different addresses
        assert_ne!(
            t1.address().to_string(),
            t2.address().to_string(),
            "Different treasury names should produce different addresses"
        );
    }

    // ─── Test 2: Simple message send between treasuries ────────────────

    #[test]
    fn test_send_between_treasuries() {
        let mut bc = Blockchain::new().expect("blockchain");

        let alice = bc.treasury("alice", 10_000_000_000).expect("alice");
        let bob = bc.treasury("bob", 10_000_000_000).expect("bob");

        // Alice sends 1 TOS to Bob
        let msg = alice.build_message(bob.address(), 1_000_000_000, false, None);
        let result = bc.send_message(msg).expect("send should succeed");

        // Should have at least 1 transaction
        assert!(
            result.transaction_count() >= 1,
            "Should have at least 1 transaction, got {}",
            result.transaction_count()
        );
    }

    // ─── Test 3: Snapshot save/restore ──────────────────────────────────

    #[test]
    fn test_snapshot_restore() {
        let mut bc = Blockchain::new().expect("blockchain");

        let alice = bc.treasury("alice", 10_000_000_000).expect("alice");
        let alice_addr = alice.address().clone();

        // Save snapshot
        let snap = bc.snapshot();

        // Create another treasury (changes state)
        let bob = bc.treasury("bob", 5_000_000_000).expect("bob");
        let bob_addr = bob.address().clone();

        // Bob should exist
        assert!(bc.get_account(&bob_addr).is_some(), "Bob should exist before restore");

        // Restore snapshot
        bc.restore(snap);

        // Alice should still exist
        assert!(bc.get_account(&alice_addr).is_some(), "Alice should survive restore");

        // Bob should NOT exist (was created after snapshot)
        assert!(bc.get_account(&bob_addr).is_none(), "Bob should not exist after restore");
    }

    // ─── Test 4: Blockchain time management ────────────────────────────

    #[test]
    fn test_time_management() {
        let mut bc = Blockchain::new().expect("blockchain");

        let initial_time = bc.now();
        assert!(initial_time > 0, "Initial time should be positive");

        bc.set_now(1_800_000_000);
        assert_eq!(bc.now(), 1_800_000_000);

        let initial_lt = bc.lt();
        assert!(initial_lt > 0, "Initial LT should be positive");
    }

    // ─── Test 5: MessageBuilder ────────────────────────────────────────

    #[test]
    fn test_message_builder_internal() {
        let mut bc = Blockchain::new().expect("blockchain");
        let alice = bc.treasury("alice", 10_000_000_000).expect("alice");
        let bob = bc.treasury("bob", 10_000_000_000).expect("bob");

        let msg = MessageBuilder::internal(alice.address(), bob.address(), 500_000_000)
            .bounce(false)
            .build();

        // Message should be constructable without error
        assert!(msg.is_internal(), "Should be an internal message");
    }

    #[test]
    fn test_message_builder_external() {
        let mut bc = Blockchain::new().expect("blockchain");
        let alice = bc.treasury("alice", 10_000_000_000).expect("alice");

        let msg = MessageBuilder::external(alice.address()).build();

        // Message should be constructable
        assert!(!msg.is_internal(), "Should not be an internal message");
    }

    // ─── Test 6: How a get-method ends ─────────────────────────────────

    // For code that ignores the method id: the expected exit code and final stack, bottom to
    // top (`None` stands for the gas consumed), as the C++ VM leaves them. Out of gas keeps only
    // the gas consumed, an exception keeps its argument, and a program that jumps into the
    // default exception handler keeps everything below the exit code it chose; 13 chosen by a
    // program is not out of gas.
    #[test]
    fn test_get_method_reports_how_the_vm_ended() {
        use chain_block::{tos_method_id, Account, BuilderData, Cell, MsgAddressInt, StateInit};
        let method_id = i64::from(tos_method_id("ending"));
        let cases: [(&str, &[u8], i32, Vec<Option<i64>>); 5] = [
            // PUSHINT 7, PUSHCONT {}, AGAIN
            ("out of gas", &[0x77, 0x90, 0xEA], -14, vec![None]),
            // PUSHINT 7, THROW 6
            ("throw", &[0x77, 0xF2, 0x06], 6, vec![Some(0)]),
            // PUSHINT 42, THROWARG 9
            ("throwarg", &[0x80, 42, 0xF2, 0xC8, 0x09], 9, vec![Some(42)]),
            // PUSHINT 5, PUSHINT 7, PUSHINT 13, PUSH c2, JMPX
            (
                "jump into the default handler",
                &[0x75, 0x77, 0x80, 0x0D, 0xED, 0x42, 0xD9],
                13,
                vec![Some(method_id), Some(5), Some(7)],
            ),
            // THROW 13
            ("throw 13", &[0xF2, 0x0D], 13, vec![Some(0)]),
        ];
        let mut bc = Blockchain::new().expect("blockchain");
        let address = MsgAddressInt::standard(0, [0x11; 32]);
        for (name, code, exit_code, stack) in cases {
            let mut state_init = StateInit::default();
            let code = BuilderData::with_raw(code.to_vec(), code.len() * 8).expect("code");
            state_init.set_code(code.into_cell().expect("code cell"));
            state_init.set_data(Cell::default());
            let account = Account::active_standard([0x11; 32], 1_000_000_000, 0, 0, state_init);
            bc.set_account(address.clone(), account);
            let result =
                bc.run_get_method_with_gas(&address, "ending", vec![], 10_000).expect(name);
            assert_eq!(result.exit_code, exit_code, "{name}");
            let actual: Vec<i64> = result
                .stack
                .iter()
                .map(|x| x.as_integer_value(i64::MIN..=i64::MAX).expect(name))
                .collect();
            let expected: Vec<i64> = stack.iter().map(|x| x.unwrap_or(result.gas_used)).collect();
            assert_eq!(actual, expected, "{name}");
        }
    }
}
