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

impl<'a, Elt: 'a + Clone> std::iter::FromIterator<&'a Elt> for PerCpuBuffer<Elt> {
    /// # Panics
    ///
    /// This function will panic if the iterator holds a number of item different than the
    /// detected number of CPUs. See `rebpf::libbpf::libbpf_num_possible_cpus`.
    fn from_iter<It: IntoIterator<Item = &'a Elt>>(iter: It) -> Self {
        let iter = iter.into_iter();
        let mut ret = PerCpuBuffer::<Elt>::new().expect("Couldn't allocate a per-CPU buffer");
        let mut added = 0;
        for (i, item) in iter.enumerate() {
            assert!(
                i < ret.nb_elements,
                "There are more elements than expected."
            );
            unsafe {
                let dst = ret
                    .data
                    .as_mut_ptr()
                    .add(i * PerCpuBuffer::<Elt>::element_size())
                    as *mut Elt;
                std::ptr::write(dst, item.clone())
            }
            added += 1;
        }
        assert!(
            added == ret.nb_elements,
            "There weren't enough elements to fill the buffer."
        );
        ret
    }
}

impl<'a, T: Sized> IntoIterator for &'a PerCpuBuffer<T> {
    type Item = &'a T;
    type IntoIter = PerCpuIterator<'a, T>;

    /// # Panics
    ///
    /// Will panic if the buffer hasn't been initialized. This is typically a sign of
    /// a bug within the `rebpf` code itself.
    fn into_iter(self) -> Self::IntoIter {
        assert!(self.initialized, "The buffer wasn't marked as initialized.");
        PerCpuIterator::new(self)
    }
}

pub struct PerCpuIterator<'a, T> {
    buffer: &'a PerCpuBuffer<T>,
    next_item: usize,
    size: usize,
}

impl<'a, T> PerCpuIterator<'a, T> {
    fn new(buffer: &PerCpuBuffer<T>) -> PerCpuIterator<T> {
        PerCpuIterator {
            buffer,
            next_item: 0,
            size: buffer.data.len() / PerCpuBuffer::<T>::element_size(),
        }
    }
}

impl<'a, T> Iterator for PerCpuIterator<'a, T> {
    type Item = &'a T;
    fn next(&mut self) -> Option<Self::Item> {
        if self.next_item >= self.size {
            None
        } else {
            let offset = PerCpuBuffer::<T>::element_size() * self.next_item;
            self.next_item += 1;
            Some(unsafe { std::mem::transmute::<&'a u8, &'a T>(&self.buffer.data[offset]) })
        }
    }
}
