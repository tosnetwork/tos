/*
 * Copyright (C) 2019-2024 EverX. All Rights Reserved.
 * Modifications Copyright (C) 2025-2026 RSquad Blockchain Lab.
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This file has been modified from its original version.
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
mod common;
use common::*;
use chain_block::ExceptionCode;
use tos_vm::{
    boolean, int,
    stack::{integer::IntegerData, Stack, StackItem},
};

mod ldtomis {
    use super::*;

    #[test]
    fn test_normal_flow() {
        test_case(
            "PUSHSLICE x1568_
            LDTOMIS
            SEMPTY",
        )
        .expect_stack(Stack::new().push(int!(86)).push(boolean!(true)));

        test_case(
            "PUSHSLICE x248568_
            LDVARUINT16
            SEMPTY",
        )
        .expect_stack(Stack::new().push(int!(18518)).push(boolean!(true)));

        test_case(
            "PUSHSLICE x24856212348_
            LDVARUINT16
            LDTOMIS
            SEMPTY",
        )
        .expect_stack(Stack::new().push(int!(18518)).push(int!(4660)).push(boolean!(true)));
    }

    #[test]
    fn test_cell_underflow() {
        test_case(
            "PUSHSLICE x158_
            LDTOMIS",
        )
        .expect_failure(ExceptionCode::CellUnderflow);
    }
}

mod ldvarint16 {
    use super::*;

    #[test]
    fn test_normal_flow() {
        test_case(
            "PUSHSLICE x1568_
            LDVARINT16
            SEMPTY",
        )
        .expect_stack(Stack::new().push(int!(86)).push(boolean!(true)));

        test_case(
            "PUSHINT 100
            PUSHINT 2
            NEWC
            STU 4
            STI 16
            ENDC
            CTOS
            LDVARINT16
            SEMPTY",
        )
        .expect_stack(Stack::new().push(int!(100)).push(boolean!(true)));

        test_case(
            "PUSHSLICE x24856212348_
            LDVARINT16
            LDVARINT16
            SEMPTY",
        )
        .expect_stack(Stack::new().push(int!(18518)).push(int!(4660)).push(boolean!(true)));
    }

    #[test]
    fn test_cell_underflow() {
        test_case(
            "PUSHSLICE x158_
            LDVARINT16",
        )
        .expect_failure(ExceptionCode::CellUnderflow);
    }
}

mod sttomis {
    use super::*;

    #[test]
    fn test_normal_flow() {
        test_case(
            "NEWC
            PUSHINT 86
            STTOMIS
            ENDC
            CTOS

            LDTOMIS
            SEMPTY",
        )
        .expect_stack(Stack::new().push(int!(86)).push(boolean!(true)));

        test_case(
            "NEWC
            PUSHINT 18518
            STTOMIS
            ENDC
            CTOS

            LDVARUINT16
            SEMPTY",
        )
        .expect_stack(Stack::new().push(int!(18518)).push(boolean!(true)));

        test_case(
            "NEWC
            PUSHINT 18518
            STTOMIS
            PUSHINT 4660
            STTOMIS
            ENDC
            CTOS

            LDVARUINT16
            LDTOMIS
            SEMPTY",
        )
        .expect_stack(Stack::new().push(int!(18518)).push(int!(4660)).push(boolean!(true)));
    }

    #[test]
    fn test_range_check() {
        test_case(
            "NEWC
            PUSHINT -1
            STTOMIS",
        )
        .expect_failure(ExceptionCode::RangeCheckError);

        test_case(
            "NEWC
            PUSHINT 1
            PUSHINT 120
            LSHIFT
            STTOMIS
            ENDC",
        )
        .expect_failure(ExceptionCode::RangeCheckError);

        test_case(
            "NEWC
            PUSHINT 1
            PUSHINT 120
            LSHIFT
            DEC
            STTOMIS
            ENDC",
        )
        .expect_success();

        test_case(
            "NEWC
            PUSHINT 0
            STTOMIS",
        )
        .expect_success();
    }
}

mod stvarint16 {
    use super::*;

    #[test]
    fn test_normal_flow() {
        test_case(
            "NEWC
            PUSHINT 86
            STVARINT16
            ENDC
            CTOS

            LDVARINT16
            SEMPTY",
        )
        .expect_stack(Stack::new().push(int!(86)).push(boolean!(true)));

        test_case(
            "NEWC
            PUSHINT 18518
            STVARINT16
            ENDC
            CTOS

            LDVARINT16
            SEMPTY",
        )
        .expect_stack(Stack::new().push(int!(18518)).push(boolean!(true)));

        test_case(
            "NEWC
            PUSHINT 18518
            STVARINT16
            PUSHINT 4660
            STVARINT16
            ENDC
            CTOS

            LDVARINT16
            LDVARINT16
            SEMPTY",
        )
        .expect_stack(Stack::new().push(int!(18518)).push(int!(4660)).push(boolean!(true)));
    }

    #[test]
    fn test_range_check() {
        test_case(
            "NEWC
            PUSHINT 1
            PUSHINT 119
            LSHIFT
            STVARINT16
            ENDC",
        )
        .expect_failure(ExceptionCode::RangeCheckError);

        test_case(
            "NEWC
            PUSHINT 1
            PUSHINT 119
            LSHIFT
            INC
            NEGATE
            STVARINT16
            ENDC",
        )
        .expect_failure(ExceptionCode::RangeCheckError);

        test_case(
            "NEWC
            PUSHINT 1
            PUSHINT 119
            LSHIFT
            DEC
            STVARINT16
            ENDC",
        )
        .expect_success();

        test_case(
            "NEWC
            PUSHINT 1
            PUSHINT 119
            LSHIFT
            NEGATE
            STVARINT16
            ENDC",
        )
        .expect_success();
    }
}

mod stvaruint32 {
    use super::*;

    #[test]
    fn test_normal_flow() {
        test_case(
            "NEWC
            PUSHINT 86
            STVARUINT32
            ENDC
            CTOS

            LDVARUINT32
            SEMPTY",
        )
        .expect_stack(Stack::new().push(int!(86)).push(boolean!(true)));

        test_case(
            "NEWC
            PUSHINT 18518
            STVARUINT32
            ENDC
            CTOS

            LDVARUINT32
            SEMPTY",
        )
        .expect_stack(Stack::new().push(int!(18518)).push(boolean!(true)));

        test_case(
            "NEWC
            PUSHINT 18518
            STVARUINT32
            PUSHINT 4660
            STVARUINT32
            ENDC
            CTOS

            LDVARUINT32
            LDVARUINT32
            SEMPTY",
        )
        .expect_stack(Stack::new().push(int!(18518)).push(int!(4660)).push(boolean!(true)));

        test_case(
            "NEWC
            PUSHPOW2DEC 248 ; FFF...FF (31 bytes)
            STVARUINT32
            PUSHINT 4660
            STVARUINT32
            ENDC
            CTOS

            LDVARUINT32
            LDVARUINT32
            SEMPTY",
        )
        .expect_stack(
            Stack::new()
                .push(int!(parse "452312848583266388373324160190187140051835877600158453279131187530910662655"))
                .push(int!(4660))
                .push(boolean!(true))
        );
    }

    #[test]
    fn test_range_check() {
        test_case(
            "NEWC
            PUSHINT -1
            STVARUINT32",
        )
        .expect_failure(ExceptionCode::RangeCheckError);

        test_case(
            "NEWC
            PUSHINT 1
            PUSHINT 248
            LSHIFT
            STVARUINT32
            ENDC",
        )
        .expect_failure(ExceptionCode::RangeCheckError);

        test_case(
            "NEWC
            PUSHINT 1
            PUSHINT 248
            LSHIFT
            DEC
            STVARUINT32
            ENDC",
        )
        .expect_success();

        test_case(
            "NEWC
            PUSHINT 0
            STVARUINT32",
        )
        .expect_success();
    }
}

mod stvarint32 {
    use super::*;

    #[test]
    fn test_normal_flow() {
        test_case(
            "NEWC
            PUSHINT 86
            STVARINT32
            ENDC
            CTOS

            LDVARINT32
            SEMPTY",
        )
        .expect_stack(Stack::new().push(int!(86)).push(boolean!(true)));

        test_case(
            "NEWC
            PUSHINT 18518
            STVARINT32
            ENDC
            CTOS

            LDVARINT32
            SEMPTY",
        )
        .expect_stack(Stack::new().push(int!(18518)).push(boolean!(true)));

        test_case(
            "NEWC
            PUSHINT 18518
            STVARINT32
            PUSHINT 4660
            STVARINT32
            ENDC
            CTOS

            LDVARINT32
            LDVARINT32
            SEMPTY",
        )
        .expect_stack(Stack::new().push(int!(18518)).push(int!(4660)).push(boolean!(true)));
    }

    #[test]
    fn test_range_check() {
        test_case(
            "NEWC
            PUSHINT 1
            PUSHINT 247
            LSHIFT
            STVARINT32
            ENDC",
        )
        .expect_failure(ExceptionCode::RangeCheckError);

        test_case(
            "NEWC
            PUSHINT 1
            PUSHINT 247
            LSHIFT
            INC
            NEGATE
            STVARINT32
            ENDC",
        )
        .expect_failure(ExceptionCode::RangeCheckError);

        test_case(
            "NEWC
            PUSHINT 1
            PUSHINT 247
            LSHIFT
            DEC
            STVARINT32
            ENDC",
        )
        .expect_success();

        test_case(
            "NEWC
            PUSHINT 1
            PUSHINT 247
            LSHIFT
            NEGATE
            STVARINT32
            ENDC",
        )
        .expect_success();

        test_case(
            "NEWC
            PUSHPOW2DEC 247
            STVARINT32
            ENDC",
        )
        .expect_success();

        test_case(
            "NEWC
            PUSHNEGPOW2 247
            STVARINT32
            ENDC",
        )
        .expect_success();
    }
}

#[test]
fn test_stvaruint32_nan() {
    test_case(
        "
        NEWC
        PUSHNAN
        STVARUINT32
    ",
    )
    .expect_failure(ExceptionCode::RangeCheckError);
}
