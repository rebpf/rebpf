#[allow(unused)]
use crate::error::{Error, GenericError, LibbpfError, Result};

#[allow(unused)]
use std::{
    ffi::{CStr, CString},
    os::raw::{self, c_void},
    path::Path,
};

/// This module contains utils functions for interal use.

#[cfg(feature = "userspace")]
pub(crate) fn path_to_str(path: &Path) -> Result<&str> {
    path.to_str()
        .ok_or(Error::Generic(GenericError::InvalidPath))
}

#[cfg(feature = "userspace")]
pub(crate) fn str_to_cstring(s: &str) -> Result<CString> {
    let cstring_r = CString::new(s);
    match cstring_r {
        Ok(cstring) => Ok(cstring),
        Err(nul_error) => map_generic_error(GenericError::CStringConversion(nul_error)),
    }
}

#[cfg(feature = "userspace")]
pub(crate) fn c_char_pointer_to_string(c_char_p: *const raw::c_char) -> Result<String> {
    let cs = unsafe { CStr::from_ptr(c_char_p) };
    match cs.to_str() {
        Ok(s) => Ok(String::from(s)),
        Err(e) => map_generic_error(GenericError::CCharConversion(e)),
    }
}

#[allow(unused)]
pub(crate) fn to_const_c_void<T>(v: &T) -> *const c_void {
    v as *const T as *const c_void
}

#[allow(unused)]
pub(crate) fn to_mut_c_void<T>(v: &mut T) -> *mut c_void {
    v as *mut T as *mut c_void
}

#[cfg(feature = "userspace")]
pub(crate) fn map_generic_error<T>(e: GenericError) -> Result<T> {
    Err(Error::Generic(e))
}

#[allow(unused)]
pub(crate) fn map_libbpf_error<T>(function_name: &str, e: LibbpfError) -> Result<T> {
    Err(Error::Libbpf(function_name.to_owned(), e))
}

#[allow(unused)]
pub(crate) fn map_libbpf_sys_error<T>(function_name: &str, e: i32) -> Result<T> {
    Err(Error::Libbpf(
        function_name.to_owned(),
        LibbpfError::LibbpfSys(e),
    ))
}
