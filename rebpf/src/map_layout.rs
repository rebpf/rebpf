//! This module contains a MapLayout definition. MapLayout allows to
//! write and read values from bpf maps in a safe way.

use lazy_static::lazy_static;
use maybe_uninit::MaybeUninit;
use std::ffi::c_void;
use std::os::raw;

pub trait PtrCheckedMut<T, L: MapLayout<T> + ?Sized> {
    /// Get a pointer to the beginning of the buffer to pass
    /// to the BPF system calls for them to write into.
    ///
    /// # Panics
    ///
    /// This function may panic if the buffer doesn't hold the invariants
    /// required by the layout.
    fn ptr_checked_mut(&mut self) -> *mut c_void;
}

pub trait PtrChecked<T, L: MapLayout<T> + ?Sized> {
    /// Get a pointer to the beginning of the buffer to pass
    /// to the BPF system calls for them to read from.
    ///
    /// # Panics
    ///
    /// This function may panic if the buffer doesn't hold the invariants
    /// required by the layout.
    fn ptr_checked(&self) -> *const c_void;
}

/// Generic marker trait for the various types of data layout
/// expected by the BPF subsystem.
pub trait MapLayout<T> {
    /// The canonical buffer form for this layout
    type Buffer: PtrChecked<T, Self>;
    /// A buffer that can be written into from unsafe code.
    /// Usually a close relative of Buffer with some MaybeUninit wrapping
    type WritableBuffer: PtrCheckedMut<T, Self>;

    /// Initialize a buffer that can directly be read by the BPF calls expecting
    /// this layout. The contents of the buffer will be initialized via the
    /// `value_gen` callback, which may be called multiple times depending on the
    /// particular layout.
    ///
    /// This function is not expected to panic.
    fn allocate(value_gen: impl FnMut() -> T) -> Self::Buffer;

    /// Create a Rust-side buffer that obeys the layout requirements for
    /// this layout, with uninitialized contents. Use the `transmute` function
    /// after the BPF call to change it into a form that can be used from Rust code.
    ///
    /// This function is not expected to panic.
    fn allocate_write() -> Self::WritableBuffer;

    /// Transmute a `WritableBuffer` into its `Buffer` equivalent to be able to
    /// read and modify its content safely from the Rust side.
    ///
    /// # Safety
    ///
    /// The caller must make sure that the contents of the buffer have actually
    /// been written into valid values, for instance via a successful
    /// `bpf_map_lookup_elem` call.
    ///
    /// # Panics
    ///
    /// This function is allowed to panic, see the details on the particular
    /// implementations
    unsafe fn transmute(buffer: Self::WritableBuffer) -> Self::Buffer;
}

/// The simplest data layout, a single, scalar value.
/// Used by the most basic BPF maps, such as the Array and HashMap
pub struct ScalarLayout;
impl<T> MapLayout<T> for ScalarLayout {
    type WritableBuffer = MaybeUninit<T>;
    type Buffer = T;

    fn allocate(mut value_gen: impl FnMut() -> T) -> Self::Buffer {
        value_gen()
    }

    fn allocate_write() -> Self::WritableBuffer {
        MaybeUninit::uninit()
    }

    /// # Panics
    ///
    /// This function will not panic.
    unsafe fn transmute(buffer: Self::WritableBuffer) -> Self::Buffer {
        buffer.assume_init()
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

/// Individual value wrapper for the PerCpuLayout
#[repr(align(8))]
#[derive(Debug, Default)]
pub struct PerCpuValue<T>(T);

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

impl<T> AsMut<T> for PerCpuValue<T> {
    fn as_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

/// Memory layout matching per-CPU values, with its specificities.
/// Notably, the kernel rounds up the size of an individual value to a multiple
/// of 8, which means we cannot use a simple packed layout as in a Vec.
pub struct PerCpuLayout;

lazy_static! {
    pub(crate) static ref NB_CPUS: usize = crate::libbpf::libbpf_num_possible_cpus()
        .expect("Couldn't get the number of CPUs from BPF")
        as usize;
}

impl PerCpuLayout {
    fn nb_cpus() -> usize {
        *NB_CPUS
    }
}

impl<T> MapLayout<T> for PerCpuLayout {
    type Buffer = Box<[PerCpuValue<T>]>;
    type WritableBuffer = Box<[MaybeUninit<PerCpuValue<T>>]>;
    fn allocate(mut value_gen: impl FnMut() -> T) -> Self::Buffer {
        std::iter::repeat_with(|| PerCpuValue(value_gen()))
            .take(Self::nb_cpus())
            .collect::<Vec<_>>()
            .into_boxed_slice()
    }

    fn allocate_write() -> Self::WritableBuffer {
        std::iter::repeat_with(MaybeUninit::uninit)
            .take(Self::nb_cpus())
            .collect::<Vec<_>>()
            .into_boxed_slice()
    }

    /// # Panics
    ///
    /// This will panic if the input buffer hasn't a size exactly equal to the
    /// number of CPUs on the system, as exposed via `PerCpuLayout::nb_cpus()`
    unsafe fn transmute(buffer: Self::WritableBuffer) -> Self::Buffer {
        assert!(buffer.len() == Self::nb_cpus(), "size mismatch");
        let mut buffer = std::mem::ManuallyDrop::new(buffer);
        // Transmute the underlying data into initialized types
        let transmuted = core::slice::from_raw_parts_mut(
            buffer.as_mut_ptr() as *mut PerCpuValue<T>,
            buffer.len(),
        );
        Box::from_raw(transmuted)
    }
}

impl<T> PtrChecked<T, PerCpuLayout> for Box<[PerCpuValue<T>]> {
    fn ptr_checked(&self) -> *const c_void {
        assert!(self.len() == PerCpuLayout::nb_cpus(), "size mismatch");
        self.as_ptr() as *const c_void
    }
}

impl<T> PtrCheckedMut<T, PerCpuLayout> for Box<[MaybeUninit<PerCpuValue<T>>]> {
    fn ptr_checked_mut(&mut self) -> *mut c_void {
        assert!(self.len() == PerCpuLayout::nb_cpus(), "size mismatch");
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
