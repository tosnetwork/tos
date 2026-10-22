//! Scoped unit-test controls; this module is absent from every non-test library.
use anyhow::Result;
use std::{cell::RefCell, process::Command};
type Manager = Box<dyn FnMut(&mut Command) -> Result<String>>;
type Boundary = Box<dyn FnMut(&str) -> Result<()>>;
thread_local! {
    static MANAGER: RefCell<Option<Manager>> = const { RefCell::new(None) };
    static BOUNDARY: RefCell<Option<Boundary>> = const { RefCell::new(None) };
}
pub(crate) struct Scope;
impl Scope {
    pub(crate) fn install(manager: Manager, boundary: Boundary) -> Self {
        MANAGER.with(|slot| {
            assert!(slot.borrow().is_none());
            *slot.borrow_mut() = Some(manager);
        });
        BOUNDARY.with(|slot| {
            assert!(slot.borrow().is_none());
            *slot.borrow_mut() = Some(boundary);
        });
        Self
    }
}
impl Drop for Scope {
    fn drop(&mut self) {
        MANAGER.with(|slot| *slot.borrow_mut() = None);
        BOUNDARY.with(|slot| *slot.borrow_mut() = None);
    }
}
pub(crate) fn command(command: &mut Command) -> Option<Result<String>> {
    if command.get_program() != "systemctl" {
        return None;
    }
    MANAGER.with(|slot| slot.borrow_mut().as_mut().map(|manager| manager(command)))
}
pub(crate) fn boundary(name: &str) -> Result<()> {
    BOUNDARY.with(|slot| match slot.borrow_mut().as_mut() {
        Some(hook) => hook(name),
        None => Ok(()),
    })
}
