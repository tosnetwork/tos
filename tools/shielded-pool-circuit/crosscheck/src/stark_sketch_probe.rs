/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! What the inner loops of a FRI verifier cost in this VM.
//!
//! Nothing here is part of V1 and nothing here is a STARK verifier. A whole
//! verifier is weeks of work; what decides whether it is worth starting is
//! the cost of the two loops it is almost entirely made of, and those can be
//! written and measured in an afternoon:
//!
//!   * a Merkle authentication path, which a verifier walks once per query
//!     per commitment -- about 3,700 hash compressions for the parameters
//!     that reach 128 bits of proven security;
//!   * one FRI folding step in the extension field, which it does once per
//!     query per layer.
//!
//! Everything else in a verifier -- transcript, out-of-domain evaluation,
//! DEEP composition -- is a fixed cost that does not scale with the query
//! count, so getting these two right brackets the answer.
//!
//! The field is Goldilocks, p = 2^64 - 2^32 + 1, with a cubic extension,
//! because the size measurement showed a quadratic extension cannot reach
//! 128 bits of proven security at any query count.

use chain_block::{BuilderData, Cell, IBitstring, MsgAddressInt, Serializable, StateInit};
use tos_sandbox::{compile_func, Blockchain, MessageBuilder};
use tos_vm::stack::integer::IntegerData;
use tos_vm::stack::StackItem;

use crate::{stdlib_path, CrossCheckError, Result, ACTIVE_VERSION, TOS};

const PROBE: &str = r#"
;; --- Goldilocks -----------------------------------------------------------
;; p = 2^64 - 2^32 + 1. A 64-bit prime fits a TVM integer with room for the
;; 128-bit product, which is why a small field costs so much less here than
;; the 255-bit one Groth16 forces.
int gl_p() asm "18446744069414584321 PUSHINT";

int gl_mul(int a, int b) inline {
  (_, int r) = muldivmod(a, b, gl_p());
  return r;
}

;; The same product reduced with shifts instead of a division, using the
;; structure of p: 2^64 = 2^32 - 1 and 2^96 = -1 modulo p. Every Goldilocks
;; implementation does this; the division above is what a first draft does.
int gl_mul_fast(int a, int b) inline {
  int x = a * b;
  int x0 = x & 0xffffffffffffffff;
  int x1 = (x >> 64) & 0xffffffff;
  int x2 = x >> 96;
  int t = x0 + (x1 << 32) - x1 - x2;
  ;; Two conditional corrections are enough for inputs already reduced.
  if (t < 0) { t += gl_p(); }
  if (t < 0) { t += gl_p(); }
  if (t >= gl_p()) { t -= gl_p(); }
  if (t >= gl_p()) { t -= gl_p(); }
  return t;
}

(int, int, int) ext_mul_fast(int a0, int a1, int a2, int b0, int b1, int b2) inline {
  int c0 = gl_mul_fast(a0, b0);
  int c1 = gl_add(gl_mul_fast(a0, b1), gl_mul_fast(a1, b0));
  int c2 = gl_add(gl_add(gl_mul_fast(a0, b2), gl_mul_fast(a1, b1)), gl_mul_fast(a2, b0));
  int c3 = gl_add(gl_mul_fast(a1, b2), gl_mul_fast(a2, b1));
  int c4 = gl_mul_fast(a2, b2);
  return (gl_add(c0, c3), gl_add(gl_add(c1, c3), c4), gl_add(c2, c4));
}

int gl_add(int a, int b) inline {
  int s = a + b;
  return s >= gl_p() ? s - gl_p() : s;
}

;; --- cubic extension ------------------------------------------------------
;; Elements are a0 + a1*u + a2*u^2 with u^3 = u + 1, which is the shape most
;; Goldilocks implementations use. The schoolbook product is nine base
;; multiplications; a verifier would use Karatsuba, so this is the pessimistic
;; count.
(int, int, int) ext_mul(int a0, int a1, int a2, int b0, int b1, int b2) inline {
  int c0 = gl_mul(a0, b0);
  int c1 = gl_add(gl_mul(a0, b1), gl_mul(a1, b0));
  int c2 = gl_add(gl_add(gl_mul(a0, b2), gl_mul(a1, b1)), gl_mul(a2, b0));
  int c3 = gl_add(gl_mul(a1, b2), gl_mul(a2, b1));
  int c4 = gl_mul(a2, b2);
  ;; u^3 = u + 1 and u^4 = u^2 + u
  int r0 = gl_add(c0, c3);
  int r1 = gl_add(gl_add(c1, c3), c4);
  int r2 = gl_add(c2, c4);
  return (r0, r1, r2);
}

;; --- one Merkle authentication path ---------------------------------------
;; The path is a chain of cells, each holding one 256-bit sibling and a
;; reference to the next. Two children are hashed as 64 bytes with SHA256,
;; which is what a verifier does at every level of every query.
int merkle_root(int leaf, cell path, int index, int depth) impure {
  int node = leaf;
  int level = 0;
  while (level < depth) {
    slice s = path.begin_parse();
    int sibling = s~load_uint(256);
    cell next = s.slice_refs() > 0 ? s~load_ref() : path;
    builder pair = ((index >> level) & 1) == 0
      ? begin_cell().store_uint(node, 256).store_uint(sibling, 256)
      : begin_cell().store_uint(sibling, 256).store_uint(node, 256);
    node = string_hash(pair.end_cell().begin_parse());
    path = next;
    level = level + 1;
  }
  return node;
}

;; --- one FRI folding step -------------------------------------------------
;; Folding by eight means interpolating the eight values that sit over one
;; point of the next layer and evaluating the result at the challenge. The
;; loop below is that work by count -- twenty-four extension multiplications
;; and as many additions -- rather than that work by meaning: what is being
;; measured is what the VM charges for it.
(int, int, int) fri_fold(cell values, int a0, int a1, int a2) impure {
  slice s = values.begin_parse();
  int acc0 = 0;
  int acc1 = 0;
  int acc2 = 0;
  int i = 0;
  while (i < 8) {
    int v0 = s~load_uint(64);
    int v1 = s~load_uint(64);
    int v2 = s~load_uint(64);
    ;; acc = acc * alpha + v, three extension multiplications' worth of work
    ;; per value once the Horner step and the twiddle are counted.
    (acc0, acc1, acc2) = ext_mul(acc0, acc1, acc2, a0, a1, a2);
    (int t0, int t1, int t2) = ext_mul(v0, v1, v2, a0, a1, a2);
    (acc0, acc1, acc2) = ext_mul(gl_add(acc0, t0), gl_add(acc1, t1), gl_add(acc2, t2),
                                 a0, a1, a2);
    acc0 = gl_add(acc0, v0);
    acc1 = gl_add(acc1, v1);
    acc2 = gl_add(acc2, v2);
    i = i + 1;
    if (s.slice_refs() > 0) {
      s = s~load_ref().begin_parse();
    }
  }
  return (acc0, acc1, acc2);
}

;; --- the measured entry points --------------------------------------------
int p_merkle(int leaf, cell path, int index, int depth) method_id {
  return merkle_root(leaf, path, index, depth);
}

int p_fold(cell values, int a0, int a1, int a2) method_id {
  (int r0, int r1, int r2) = fri_fold(values, a0, a1, a2);
  return gl_add(gl_add(r0, r1), r2);
}

int p_muldivmod(int rounds) method_id {
  int acc = 1;
  int i = 0;
  while (i < rounds) {
    (_, acc) = muldivmod(acc + 7, 1234567, gl_p());
    i = i + 1;
  }
  return acc;
}

int p_sha256(int rounds) method_id {
  slice sixty_four = begin_cell().store_uint(0x1234, 256).store_uint(0x5678, 256)
                       .end_cell().begin_parse();
  int acc = 0;
  int i = 0;
  while (i < rounds) {
    acc = acc ^ string_hash(sixty_four);
    i = i + 1;
  }
  return acc;
}

int p_extmul_fast(int rounds, int a0, int a1, int a2) method_id {
  int i = 0;
  int acc = 0;
  while (i < rounds) {
    (int r0, _, _) = ext_mul_fast(a0, a1, a2, a0, a1, a2);
    acc = gl_add(acc, r0);
    i = i + 1;
  }
  return acc;
}

int p_extmul(int rounds, int a0, int a1, int a2) method_id {
  int i = 0;
  int acc = 0;
  while (i < rounds) {
    (int r0, _, _) = ext_mul(a0, a1, a2, a0, a1, a2);
    acc = gl_add(acc, r0);
    i = i + 1;
  }
  return acc;
}

() recv_internal(int msg_value, cell in_msg_full, slice in_msg_body) impure { }
() recv_external(slice in_msg) impure { }
"#;

pub struct StarkSketch {
    bc: Blockchain,
    addr: MsgAddressInt,
    /// How many lines of FunC the sketch is, so the code-size half of the
    /// question has a number too.
    pub source_lines: usize,
}

impl StarkSketch {
    pub fn deploy() -> Result<Self> {
        let mut bc = Blockchain::with_global_version_and_base_workchain(ACTIVE_VERSION)?;
        bc.set_workchain(0);
        let payer = bc.treasury("stark_sketch", 1_000 * TOS)?;
        // A directory of this call's own. These probes are written from several tests at
        // once, and a shared path is truncated under a concurrent `func` reading it.
        let probe_dir = tempfile::tempdir()
            .map_err(|error| CrossCheckError::Sandbox(format!("probe directory: {error}")))?;
        let path = probe_dir.path().join("tos_stark_sketch.fc");
        std::fs::write(&path, PROBE)
            .map_err(|error| CrossCheckError::Sandbox(format!("write probe: {error}")))?;
        let code = compile_func(&[stdlib_path(), path])?;
        let si = StateInit::with_code_and_data(code, Cell::default());
        let hash = si
            .write_to_new_cell()
            .and_then(|b| b.into_cell())
            .map_err(|error| CrossCheckError::Sandbox(format!("state init: {error}")))?
            .hash(0);
        let addr = MsgAddressInt::with_params(0, hash)
            .map_err(|error| CrossCheckError::Sandbox(format!("address: {error}")))?;
        bc.send_message(
            MessageBuilder::internal(payer.address(), &addr, 2 * TOS)
                .bounce(false)
                .state_init(si)
                .body(Cell::default())
                .build(),
        )?
        .expect_success();
        // Lines that are neither blank nor a comment: what an auditor reads.
        let source_lines = PROBE
            .lines()
            .filter(|line| {
                let t = line.trim();
                !t.is_empty() && !t.starts_with(";;")
            })
            .count();
        Ok(Self { bc, addr, source_lines })
    }

    fn call(&self, method: &str, args: Vec<StackItem>) -> Result<i64> {
        let result = self
            .bc
            .run_get_method(&self.addr, method, args)
            .map_err(|error| CrossCheckError::Vm(format!("{method}: {error}")))?;
        if result.exit_code != 0 {
            return Err(CrossCheckError::Vm(format!("{method} exited {}", result.exit_code)));
        }
        Ok(result.gas_used)
    }

    fn integer(value: u64) -> Result<StackItem> {
        IntegerData::from_str_radix(&value.to_string(), 10)
            .map(StackItem::integer)
            .map_err(|error| CrossCheckError::Fixture(format!("{value}: {error}")))
    }

    /// A chain of `depth` cells, each one sibling.
    fn chain(values: &[u64], bits: usize) -> Result<Cell> {
        let mut cell: Option<Cell> = None;
        for value in values.iter().rev() {
            let mut builder = BuilderData::new();
            builder
                .append_raw(&value.to_be_bytes()[..], 64)
                .map_err(|error| CrossCheckError::Sandbox(format!("value: {error}")))?;
            if bits == 256 {
                builder
                    .append_raw(&[0u8; 24], 192)
                    .map_err(|error| CrossCheckError::Sandbox(format!("pad: {error}")))?;
            }
            if let Some(next) = cell {
                builder
                    .checked_append_reference(next)
                    .map_err(|error| CrossCheckError::Sandbox(format!("chain: {error}")))?;
            }
            cell = Some(
                builder
                    .into_cell()
                    .map_err(|error| CrossCheckError::Sandbox(format!("cell: {error}")))?,
            );
        }
        cell.ok_or_else(|| CrossCheckError::Fixture("an empty chain".to_string()))
    }

    /// The gas one authentication path of `depth` levels costs.
    pub fn merkle_path_gas(&self, depth: usize) -> Result<i64> {
        let siblings: Vec<u64> = (0..depth as u64).map(|i| 0x5eed_0000 + i).collect();
        let path = Self::chain(&siblings, 256)?;
        self.call(
            "p_merkle",
            vec![
                Self::integer(0x1234_5678)?,
                StackItem::cell(path),
                Self::integer(0b1011_0110_1101)?,
                Self::integer(depth as u64)?,
            ],
        )
    }

    /// Eight cubic-extension elements, one per cell: three 64-bit limbs each.
    fn extension_chain(count: usize) -> Result<Cell> {
        let mut cell: Option<Cell> = None;
        for index in (0..count).rev() {
            let mut builder = BuilderData::new();
            for limb in 0..3u64 {
                let value = 0x1000_0000u64 + index as u64 * 3 + limb;
                builder
                    .append_raw(&value.to_be_bytes()[..], 64)
                    .map_err(|error| CrossCheckError::Sandbox(format!("limb: {error}")))?;
            }
            if let Some(next) = cell {
                builder
                    .checked_append_reference(next)
                    .map_err(|error| CrossCheckError::Sandbox(format!("chain: {error}")))?;
            }
            cell = Some(
                builder
                    .into_cell()
                    .map_err(|error| CrossCheckError::Sandbox(format!("cell: {error}")))?,
            );
        }
        cell.ok_or_else(|| CrossCheckError::Fixture("an empty chain".to_string()))
    }

    /// The gas one folding step over eight extension elements costs.
    pub fn fold_gas(&self) -> Result<i64> {
        let cell = Self::extension_chain(8)?;
        self.call(
            "p_fold",
            vec![
                StackItem::cell(cell),
                Self::integer(7)?,
                Self::integer(11)?,
                Self::integer(13)?,
            ],
        )
    }

    /// The gas `rounds` cubic-extension multiplications cost, so the field
    /// arithmetic can be priced on its own.
    pub fn ext_mul_gas(&self, rounds: u64) -> Result<i64> {
        self.call(
            "p_extmul",
            vec![Self::integer(rounds)?, Self::integer(7)?, Self::integer(11)?, Self::integer(13)?],
        )
    }

    /// The gas one `muldivmod` over 257-bit integers costs, which is what a
    /// field multiplication reduces to.
    pub fn muldivmod_gas(&self, rounds: u64) -> Result<i64> {
        self.call("p_muldivmod", vec![Self::integer(rounds)?])
    }

    /// The gas `rounds` SHA256 hashes of sixty-four bytes cost. The
    /// instruction already exists; what is in question is only its price.
    pub fn sha256_gas(&self, rounds: u64) -> Result<i64> {
        self.call("p_sha256", vec![Self::integer(rounds)?])
    }

    /// The same, with the reduction a tuned implementation would use.
    pub fn ext_mul_fast_gas(&self, rounds: u64) -> Result<i64> {
        self.call(
            "p_extmul_fast",
            vec![Self::integer(rounds)?, Self::integer(7)?, Self::integer(11)?, Self::integer(13)?],
        )
    }
}
