/// Generic marker trait for the various types of data layout
/// expected by the BPF subsystem.
pub trait Layout {}

/// The simplest data layout, a single, scalar value.
pub struct ScalarLayout;
impl Layout for ScalarLayout {}

