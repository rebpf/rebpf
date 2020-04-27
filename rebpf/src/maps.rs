/// This crate contains traits defining common operations on BPF maps that can
/// be executed both on the userspace side and the BPF side.

/// This trait is implemented by all the map wrapper types, as
/// as convenient way to communicate their underlying types to the
/// Rust type system.
pub trait Map {
    type Key;
    type Value;
}

pub trait Lookup: Map {
    /// Lookup the map content associated with the given key.
    ///
    /// Note that the return value is a mere copy of said content.
    fn lookup(&self, key: &Self::Key) -> Option<Self::Value>;
}
