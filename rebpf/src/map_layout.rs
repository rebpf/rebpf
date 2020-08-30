//! This module contains a MapLayout definition. MapLayout allows to
//! write and read values from bpf maps in a safe way.

use lazy_static::lazy_static;
use maybe_uninit::MaybeUninit;
use std::ffi::c_void;
use std::os::raw;

/// Generic marker trait for the various types of data layout
/// expected by the BPF subsystem.
pub trait MapLayout {}

/// Shared trait to allocate a type that can serve as a valid
/// BPF buffer for a given layout. Note that the allocated value
/// will be valid for BPF use, but some mutations on it afterwards
/// might render it unfit. See the implementation details for each type
/// for more information.
pub trait LayoutBuffer<T, L: MapLayout> {
    fn allocate_buffer() -> Self;
}

pub trait PtrCheckedMut<T, L: MapLayout> {
    /// Get a pointer to the beginning of the buffer to pass
    /// to the BPF system calls for them to write into.
    ///
    /// # Panics
    ///
    /// This function may panic if the buffer doesn't hold the invariants
    /// required by the layout.
    fn ptr_checked_mut(&mut self) -> *mut c_void;
}

pub trait PtrChecked<T, L: MapLayout> {
    /// Get a pointer to the beginning of the buffer to pass
    /// to the BPF system calls for them to read from.
    ///
    /// # Panics
    ///
    /// This function may panic if the buffer doesn't hold the invariants
    /// required by the layout.
    fn ptr_checked(&self) -> *const c_void;
}

/// The simplest data layout, a single, scalar value.
pub struct ScalarLayout;
impl MapLayout for ScalarLayout {}

impl<T: Default> LayoutBuffer<T, ScalarLayout> for T {
    fn allocate_buffer() -> Self {
        Default::default()
    }
}

impl<T> LayoutBuffer<T, ScalarLayout> for MaybeUninit<T> {
    fn allocate_buffer() -> Self {
        MaybeUninit::uninit()
    }
}

impl<T> PtrCheckedMut<T, ScalarLayout> for MaybeUninit<T> {
    fn ptr_checked_mut(&mut self) -> *mut c_void {
        self.as_mut_ptr() as *mut c_void
    }
}

impl<T> PtrChecked<T, ScalarLayout> for T {
    fn ptr_checked(&self) -> *const c_void {
        self as *const T as *const c_void
    }
}

/// Memory layout matching per-CPU values, with its specificities.
/// Notably, the kernel rounds up the size of an individual value to a multiple
/// of 8, which means we cannot use a simple packed layout as in a Vec.
pub struct PerCpuLayout;
impl MapLayout for PerCpuLayout {}

/// Individual value wrapper for the PerCpuLayout
#[repr(align(8))]
#[derive(Debug, Default)]
pub struct PerCpuValue<T>(T);

lazy_static! {
    pub(crate) static ref NB_CPUS: usize = crate::libbpf::libbpf_num_possible_cpus()
        .expect("Couldn't get the number of CPUs from BPF")
        as usize;
}

impl<T> From<T> for PerCpuValue<T> {
    fn from(v: T) -> Self {
        PerCpuValue(v)
    }
}

impl<T> AsRef<T> for PerCpuValue<T> {
    fn as_ref(&self) -> &T {
        &self.0
    }
}

impl<T: Default> LayoutBuffer<T, PerCpuLayout> for Vec<PerCpuValue<T>> {
    /// Resizing the returned Vec before using it as a ReadPointer will lead to a panic.
    fn allocate_buffer() -> Self {
        std::iter::repeat_with(Default::default)
            .take(*NB_CPUS)
            .collect()
    }
}

impl<T> LayoutBuffer<T, PerCpuLayout> for Vec<MaybeUninit<PerCpuValue<T>>> {
    /// Resizing the returned Vec before using it as a ReadPointer will lead to a panic.
    fn allocate_buffer() -> Self {
        std::iter::repeat_with(MaybeUninit::uninit)
            .take(*NB_CPUS)
            .collect()
    }
}

impl<T> PtrChecked<T, PerCpuLayout> for Vec<PerCpuValue<T>> {
    fn ptr_checked(&self) -> *const c_void {
        assert!(self.len() == *NB_CPUS, "size mismatch");
        self.as_ptr() as *const c_void
    }
}

impl<T> PtrCheckedMut<T, PerCpuLayout> for Vec<MaybeUninit<PerCpuValue<T>>> {
    fn ptr_checked_mut(&mut self) -> *mut c_void {
        assert!(self.len() == *NB_CPUS, "size mismatch");
        self.as_mut_ptr() as *mut c_void
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::mem::{align_of, size_of};

    #[test]
    fn percpu_value_roundtrip() {
        // A standard type
        assert_eq!(42, *PerCpuValue::from(42).as_ref());

        // A bare type with no special trait whatsoever.
        struct NoDerive {
            content: usize,
        };
        assert_eq!(
            42,
            PerCpuValue::from(NoDerive { content: 42 }).as_ref().content
        );
    }

    #[test]
    fn layout_smaller_content() {
        assert_eq!(size_of::<PerCpuValue<u32>>(), 8);
        assert_eq!(align_of::<PerCpuValue<u32>>(), 8);
        assert_eq!(size_of::<u32>(), 4);
        assert_eq!(align_of::<u32>(), 4);

        assert_eq!(size_of::<PerCpuValue<u8>>(), 8);
        assert_eq!(align_of::<PerCpuValue<u8>>(), 8);
        assert_eq!(size_of::<u8>(), 1);
        assert_eq!(align_of::<u8>(), 1);

        assert_eq!(size_of::<PerCpuValue<(u8, u16)>>(), 8);
        assert_eq!(align_of::<PerCpuValue<(u8, u16)>>(), 8);
        assert_eq!(size_of::<(u8, u16)>(), 4);
        assert_eq!(align_of::<(u8, u16)>(), 2);
    }

    #[test]
    fn layout_bigger_content() {
        #[repr(align(16))]
        struct U8Align16(u8);
        assert_eq!(size_of::<U8Align16>(), 16);
        assert_eq!(align_of::<U8Align16>(), 16);
        assert_eq!(size_of::<PerCpuValue<U8Align16>>(), 16);
        assert_eq!(align_of::<PerCpuValue<U8Align16>>(), 16);

        struct U32X3(u32, u32, u32);
        assert_eq!(size_of::<U32X3>(), 12);
        assert_eq!(align_of::<U32X3>(), 4);
        assert_eq!(size_of::<PerCpuValue<U32X3>>(), 16);
        assert_eq!(align_of::<PerCpuValue<U32X3>>(), 8);
    }
}
