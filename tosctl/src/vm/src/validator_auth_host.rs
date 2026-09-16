use chain_block::{Cell, Result, Status};
/// Native transaction execution injects this authority; contract registers and
/// nested VMs cannot construct it. Effects remain staged until native commit.
pub trait ValidatorAuthHost: Send {
    fn checkpoint(&mut self, charge: &mut dyn FnMut(i64) -> Status) -> Result<Cell>;
    fn apply(
        &mut self,
        update: Cell,
        evidence: Cell,
        charge: &mut dyn FnMut(i64) -> Status,
    ) -> Result<Cell>;
    fn bind(
        &mut self,
        elected: Cell,
        bindings: Cell,
        charge: &mut dyn FnMut(i64) -> Status,
    ) -> Result<Cell>;
}
