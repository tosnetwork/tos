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
use crate::stack::{savelist::SaveList, SliceData, Stack, StackItem};
use chain_block::{error, Cell, ExceptionCode, Result};
use std::{fmt, mem, sync::Arc};

/// A reference from one continuation to another (a loop's body, an envelope's continuation, a
/// PushInt continuation's next one). It holds a stack item that is always a continuation, so
/// that releasing a long chain goes through the iterative release of stack items.
#[derive(Clone)]
pub struct ContEdge(StackItem);

impl ContEdge {
    pub fn new(cont: ContinuationData) -> Self {
        Self(StackItem::Continuation(Arc::new(cont)))
    }

    pub fn from_arc(cont: Arc<ContinuationData>) -> Self {
        Self(StackItem::Continuation(cont))
    }

    pub fn get(&self) -> &ContinuationData {
        match &self.0 {
            StackItem::Continuation(cont) => cont,
            _ => &EMPTY_ORDINARY,
        }
    }

    pub fn arc(&self) -> Arc<ContinuationData> {
        match &self.0 {
            StackItem::Continuation(cont) => cont.clone(),
            _ => Arc::new(ContinuationData::new_empty()),
        }
    }

    /// The continuation as a stack item (shares the continuation).
    pub fn to_item(&self) -> StackItem {
        self.0.clone()
    }

    /// Moves the edge out for releasing; the continuation that held it is being destroyed.
    pub(crate) fn take_item(&mut self) -> StackItem {
        mem::take(&mut self.0)
    }
}

static EMPTY_ORDINARY: ContinuationData = ContinuationData::new_empty();

/// A stack item in a continuation's Debug output: a continuation is named by its kind only, so
/// formatting a deep chain through saved registers or captured stacks does not recurse.
struct Shallow<'a>(&'a StackItem);

impl fmt::Debug for Shallow<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.0 {
            StackItem::Continuation(cont) => write!(f, "Continuation(<{}>)", cont.type_of),
            StackItem::Tuple(items) => write!(f, "Tuple(len {})", items.len()),
            item => write!(f, "{:?}", item),
        }
    }
}

impl fmt::Debug for ContEdge {
    // Shallow: names the kind only, so formatting a long chain does not recurse through it.
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "<{}>", self.get().type_of)
    }
}

/// The kinds of continuation of the C++ VM. Only `Ordinary` and `Envelope` carry control data
/// (nargs, a captured stack, a savelist): any other kind has `nargs = -1`, an empty stack and an
/// empty savelist, and gets control data by being wrapped in an `Envelope` (`force_cdata`).
#[derive(Clone, Debug, Default)]
pub enum ContinuationType {
    #[default]
    Ordinary,
    /// ArgContExt: its own control data, applied before the wrapped continuation runs.
    Envelope(ContEdge),
    Quit(i32),
    ExcQuit,
    /// Pushes the integer and continues with the next continuation.
    PushInt(i32, ContEdge),
    Repeat {
        body: ContEdge,
        after: ContEdge,
        count: i64,
    },
    Again {
        body: ContEdge,
    },
    Until {
        body: ContEdge,
        after: ContEdge,
    },
    While {
        cond: ContEdge,
        body: ContEdge,
        after: ContEdge,
        check_cond: bool,
    },
}

impl ContinuationType {
    /// The continuations this one refers to.
    pub fn edges(&self) -> Vec<&ContEdge> {
        match self {
            Self::Ordinary | Self::Quit(_) | Self::ExcQuit => vec![],
            Self::Envelope(next) | Self::PushInt(_, next) => vec![next],
            Self::Repeat { body, after, .. } | Self::Until { body, after } => vec![body, after],
            Self::Again { body } => vec![body],
            Self::While { cond, body, after, .. } => vec![cond, body, after],
        }
    }

    pub(crate) fn edges_mut(&mut self) -> Vec<&mut ContEdge> {
        match self {
            Self::Ordinary | Self::Quit(_) | Self::ExcQuit => vec![],
            Self::Envelope(next) | Self::PushInt(_, next) => vec![next],
            Self::Repeat { body, after, .. } | Self::Until { body, after } => vec![body, after],
            Self::Again { body } => vec![body],
            Self::While { cond, body, after, .. } => vec![cond, body, after],
        }
    }

    /// The same kind and scalar fields; the edges are compared separately.
    pub(crate) fn same_shape(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Ordinary, Self::Ordinary)
            | (Self::Envelope(_), Self::Envelope(_))
            | (Self::ExcQuit, Self::ExcQuit)
            | (Self::Again { .. }, Self::Again { .. })
            | (Self::Until { .. }, Self::Until { .. }) => true,
            (Self::Quit(x), Self::Quit(y)) => x == y,
            (Self::PushInt(x, _), Self::PushInt(y, _)) => x == y,
            (Self::Repeat { count: x, .. }, Self::Repeat { count: y, .. }) => x == y,
            (Self::While { check_cond: x, .. }, Self::While { check_cond: y, .. }) => x == y,
            _ => false,
        }
    }
}

#[derive(Clone)]
pub struct ContinuationData {
    code: SliceData,
    pub nargs: isize,
    pub savelist: SaveList,
    pub stack: Stack,
    pub type_of: ContinuationType,
}

impl PartialEq for ContinuationData {
    // Structural, with an explicit work list over saved registers, captured stacks and the
    // continuations of the kind (stack/mod.rs), so comparing long chains does not recurse.
    fn eq(&self, other: &Self) -> bool {
        crate::stack::continuations_equal(self, other)
    }
}

impl fmt::Debug for ContinuationData {
    // Shallow: nested continuations are named by their kind only.
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let saved: Vec<(usize, Shallow)> = SaveList::REGS
            .iter()
            .filter_map(|&i| self.savelist.get(i).map(|item| (i, Shallow(item))))
            .collect();
        let stack: Vec<Shallow> = self.stack.storage.iter().map(Shallow).collect();
        f.debug_struct("ContinuationData")
            .field("code", &self.code)
            .field("nargs", &self.nargs)
            .field("savelist", &saved)
            .field("stack", &stack)
            .field("type_of", &self.type_of)
            .finish()
    }
}

impl ContinuationData {
    pub const fn new_empty() -> Self {
        Self {
            code: SliceData::new_empty(),
            nargs: -1,
            savelist: SaveList::new(),
            stack: Stack::new(),
            type_of: ContinuationType::Ordinary,
        }
    }

    pub fn copy_without_stack(&self) -> Self {
        Self {
            code: self.code.clone(),
            nargs: self.nargs,
            savelist: self.savelist.clone(),
            stack: Stack::new(),
            type_of: self.type_of.clone(),
        }
    }

    /// The fields compared without following any nested item: code, nargs, kind, savelist
    /// slots in use, stack depth.
    pub(crate) fn shallow_eq(&self, other: &Self) -> bool {
        self.code == other.code
            && self.nargs == other.nargs
            && self.stack.depth() == other.stack.depth()
            && self.type_of.same_shape(&other.type_of)
            && SaveList::REGS
                .iter()
                .all(|&i| self.savelist.get(i).is_some() == other.savelist.get(i).is_some())
    }

    pub fn code(&self) -> &SliceData {
        &self.code
    }

    pub fn code_mut(&mut self) -> &mut SliceData {
        &mut self.code
    }

    /// Whether this continuation carries control data of its own: the C++ OrdCont and ArgContExt.
    pub fn has_control_data(&self) -> bool {
        matches!(self.type_of, ContinuationType::Ordinary | ContinuationType::Envelope(_))
    }

    /// C++ `has_c0`: control data whose savelist defines c0.
    pub fn has_c0(&self) -> bool {
        self.has_control_data() && self.savelist.get(0).is_some()
    }

    /// Invariant of the kinds: only Ordinary and Envelope carry control data.
    pub fn invariant_holds(&self) -> bool {
        self.has_control_data()
            || (self.nargs == -1 && self.stack.depth() == 0 && self.savelist.is_empty())
    }

    pub fn can_put_to_savelist_once(&self, i: usize) -> bool {
        self.savelist.get(i).is_none()
    }

    pub fn move_to_end(&mut self) {
        self.code = SliceData::default()
    }

    pub fn put_to_savelist(&mut self, i: usize, val: StackItem) -> Result<Option<StackItem>> {
        self.savelist.put(i, val)
    }

    pub fn remove_from_savelist(&mut self, i: usize) -> Option<StackItem> {
        self.savelist.remove(i)
    }

    pub fn with_code_and_stack(code: SliceData, stack: Stack) -> Self {
        ContinuationData {
            code,
            nargs: -1,
            savelist: SaveList::new(),
            stack,
            type_of: ContinuationType::Ordinary,
        }
    }

    pub fn with_code(code: SliceData) -> Self {
        Self::with_code_and_stack(code, Stack::new())
    }

    /// A continuation of the given kind without control data.
    pub fn with_type(type_of: ContinuationType) -> Self {
        ContinuationData {
            code: SliceData::default(),
            nargs: -1,
            savelist: SaveList::new(),
            stack: Stack::new(),
            type_of,
        }
    }

    pub fn withdraw(&mut self) -> Self {
        mem::take(self)
    }

    pub fn drain_reference(&mut self) -> Result<Cell> {
        self.code
            .checked_drain_reference()
            .map_err(|err| error!(ExceptionCode::InvalidOpcode, "drain_reference failed: {}", err))
    }
}

impl Default for ContinuationData {
    fn default() -> Self {
        Self::new_empty()
    }
}

impl fmt::Display for ContinuationData {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{{\n    type: {}\n    code: {}    nargs: {}\n    stack: ",
            self.type_of, self.code, self.nargs
        )?;
        if self.stack.depth() == 0 {
            writeln!(f, "empty")?;
        } else {
            writeln!(f)?;
            for x in self.stack.storage.iter() {
                write!(f, "        {}", x)?;
                writeln!(f)?;
            }
        }
        write!(f, "    savelist: ")?;
        if self.savelist.is_empty() {
            writeln!(f, "empty")?;
        } else {
            writeln!(f)?;
            for i in SaveList::REGS {
                if let Some(item) = self.savelist.get(i) {
                    writeln!(f, "        {}: {}", i, item)?
                }
            }
        }
        write!(f, "}}")
    }
}

impl fmt::Display for ContinuationType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let name = match self {
            ContinuationType::Ordinary => "ordinary",
            ContinuationType::Envelope(_) => "envelope",
            ContinuationType::Quit(_) => "quit",
            ContinuationType::ExcQuit => "exception-quit",
            ContinuationType::PushInt(..) => "pushint",
            ContinuationType::Repeat { .. } => "repeat",
            ContinuationType::Again { .. } => "again",
            ContinuationType::Until { .. } => "until",
            ContinuationType::While { .. } => "while",
        };
        write!(f, "{}", name)
    }
}
