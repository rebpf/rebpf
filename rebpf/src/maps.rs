/// This crate contains traits defining common operations on BPF maps that can
/// be executed both on the userspace side and the BPF side.

pub trait Lookup {
    type Key;
    type Value;
    /// Lookup the map content associated with the given key.
    ///
    /// Note that the return value is a mere copy of said content.
    fn lookup(&self, key: &Self::Key) -> Option<Self::Value>;
}
