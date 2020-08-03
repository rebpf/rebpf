use std::os::raw;

/// Generic marker trait for the various types of data layout
/// expected by the BPF subsystem.
pub trait Layout {}

/// Trait denoting a read access to an underlying memory storage
/// organised according to a specific data layout.
pub unsafe trait ReadPointer<T, L: Layout> {
    fn get_ptr(self) -> *const raw::c_void;
}

/// Trait denoting a write access to an underlying memory storage
/// organised according to a specific data layout.
pub unsafe trait WritePointer<T, L: Layout> {
    fn get_ptr_mut(self) -> *mut raw::c_void;
}

/// The simplest data layout, a single, scalar value.
pub struct ScalarLayout;
impl Layout for ScalarLayout {}

unsafe impl<T> ReadPointer<T, ScalarLayout> for &T {
    fn get_ptr(self) -> *const raw::c_void {
        self as *const T as *const raw::c_void
    }
}

unsafe impl<T> WritePointer<T, ScalarLayout> for &mut maybe_uninit::MaybeUninit<T> {
    fn get_ptr_mut(self) -> *mut raw::c_void {
        self.as_mut_ptr() as *mut raw::c_void
    }
}

