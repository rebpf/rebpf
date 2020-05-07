use crate::error::Result;
use crate::libbpf::BpfUpdateElemFlags;

/// This crate contains traits defining common operations on BPF maps that can
/// be executed both on the userspace side and the BPF side.

/// This trait is implemented by all the map wrapper types, as
/// as convenient way to communicate their underlying types to the
/// Rust type system.
pub trait Map {
    type Key;
    type Value;
}

pub trait Lookup<Value = <Self as Map>::Value>: Map {
    /// Lookup the map content associated with the given key.
    ///
    /// Note that the return value is a mere copy of said content.
    fn lookup(&self, key: &Self::Key) -> Option<Value>;

    /// Lookup the map content associated with the given key and if key
    /// is found copy content into value and return Some(()).
    fn lookup_ref(&self, key: &Self::Key, value: &mut Value) -> Option<()>;
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
