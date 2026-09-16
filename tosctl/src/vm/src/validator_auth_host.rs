use chain_block::{Cell, Result, Status};
/// What a privileged instruction lets a host spend.
///
/// Two kinds of work, priced from two different places. Gas is what the host
/// reports having done, at a price the host carries. A signature verification is
/// priced by the machine, at the tariff it already publishes for that primitive,
/// so the host never carries a second copy of a price and the two cannot drift.
///
/// A verification is reported before it is performed, not counted after. A host
/// that checked four hundred signatures and only then discovered the transaction
/// could not pay would have done the work anyway, which is the whole of the
/// attack; reporting first is what lets the charge stop the next one.
pub trait HostCharge {
    fn gas(&mut self, gas: i64) -> Status;
    fn signature_check(&mut self, suite: u16) -> Status;
}
/// Native transaction execution injects this authority; contract registers and
/// nested VMs cannot construct it. Effects remain staged until native commit.
pub trait ValidatorAuthHost: Send {
    fn checkpoint(&mut self, charge: &mut dyn HostCharge) -> Result<Cell>;
    fn apply(&mut self, update: Cell, evidence: Cell, charge: &mut dyn HostCharge) -> Result<Cell>;
    fn bind(&mut self, elected: Cell, bindings: Cell, charge: &mut dyn HostCharge)
        -> Result<Cell>;
}
