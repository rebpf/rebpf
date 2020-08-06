use crate::layout::Layout;

/// Memory layout matching per-CPU values, with its specificities.
/// Notably, the kernel rounds up the size of an individual value to a multiple
/// of 8, which means we cannot use a simple packed layout as in a Vec.
pub struct PerCpuLayout;
impl Layout for PerCpuLayout {}
