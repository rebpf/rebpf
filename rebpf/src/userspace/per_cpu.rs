use crate::error::Result;
use crate::layout::{Layout, ReadPointer, WritePointer};
use std::mem::size_of;
use std::os::raw;

/// Memory layout matching per-CPU values, with its specificities.
/// Notably, the kernel rounds up the size of an individual value to a multiple
/// of 8, which means we cannot use a simple packed layout as in a Vec.
pub struct PerCpuLayout;
impl Layout for PerCpuLayout {}

/// Buffer holding values according to the per-CPU layout.
pub struct PerCpuBuffer<T> {
    data: Vec<u8>,
    nb_elements: usize,
    output_type: std::marker::PhantomData<T>,
    initialized: bool,
}

impl<T: Sized> PerCpuBuffer<T> {
    #[inline]
    fn element_size() -> usize {
        let rem = size_of::<T>() % 8;
        if rem == 0 {
            size_of::<T>()
        } else {
            size_of::<T>() + 8 - rem
        }
    }

    pub(crate) fn new() -> Result<PerCpuBuffer<T>> {
        let nb_elements = crate::libbpf::libbpf_num_possible_cpus()? as usize;
        let buffer_size = nb_elements * Self::element_size();
        let data = vec![0u8; buffer_size];
        Ok(PerCpuBuffer {
            data,
            nb_elements,
            output_type: Default::default(),
            initialized: false,
        })
    }

    /// # Safety
    ///
    /// Call this method to mark the buffer as initialized. The caller indicates by
    /// this call that the underlying data buffer has been initialized by an external
    /// API (typically `bpf_map_lookup_elem`) and the data is conform to the expectations
    /// matching the type `T`.
    pub(crate) unsafe fn mark_as_initialized(&mut self) {
        self.initialized = true;
    }
}

unsafe impl<T> ReadPointer<T, PerCpuLayout> for &PerCpuBuffer<T> {
    fn get_ptr(self) -> *const raw::c_void {
        self.data.as_ptr() as *const raw::c_void
    }
}

unsafe impl<T> WritePointer<T, PerCpuLayout> for &mut PerCpuBuffer<T> {
    fn get_ptr_mut(self) -> *mut raw::c_void {
        self.data.as_mut_ptr() as *mut raw::c_void
    }
}
