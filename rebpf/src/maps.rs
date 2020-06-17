use crate::error::Result;
use crate::libbpf::BpfUpdateElemFlags;

/// This module contains traits defining common operations on BPF maps that can
/// be executed both on the userspace side and the BPF side.

/// This trait is implemented by all the map wrapper types, as
/// as convenient way to communicate their underlying types to the
/// Rust type system.
pub trait Map {
    type Key;
    type Value;
}

pub trait Update: Map {
    /// Update a value inside the map.
    ///
    /// This operation is considered as atomic.
    fn update<'a>(
        &'a mut self,
        key: &Self::Key,
        value: &Self::Value,
        flags: BpfUpdateElemFlags,
    ) -> Result<()>;
}
