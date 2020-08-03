//! This module contains utils functions to write bpf programs.

#[allow(unused)]
use crate::error::{Error, GenericError, Result};

/// Returns a slice of the given slice from the byte range [begin, end).
/// Differently from &[begin..end] this method is allowed in bpf programs.
#[allow(unused)]
#[inline(always)]
pub fn get_unsafe_slice_range(slice: &[u8], begin: usize, end: usize) -> &[u8] {
    unsafe { std::slice::from_raw_parts(slice.as_ptr().add(begin), end - begin) }
}

/*
/// Returns a slice of the given slice from the byte range [begin, end) checking slice length.
/// Differently from &[begin..end] this method is allowed in bpf programs.
// #[allow(unused)]
// #[inline(always)]
// pub fn get_slice_range<T>(slice: &[T], begin: usize, end: usize) -> Result<&[T]> {
//     if slice.len() < end - begin {
//         return Err(Error::Generic(GenericError::OutOfIndex))
//     }
//     Ok(
//         get_unsafe_slice_range(slice, begin, end)
//     )
// }
*/
