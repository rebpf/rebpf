use crate::error::{Error, GenericError, LibbpfError};
use std::{
    ffi::{CStr, CString},
    os::raw::{self, c_void},
    path::Path,
};

/// This module contains utils functions.

pub(crate) fn path_to_str(path: &Path) -> Result<&str, Error> {
    path.to_str().ok_or(Error::Generic(GenericError::InvalidPath))
}

pub(crate) fn str_to_cstring(s: &str) -> Result<CString, Error> {
    let cstring_r = CString::new(s);
    match cstring_r {
        Ok(cstring) => Ok(cstring),
        Err(nul_error) => map_generic_error(GenericError::CStringConversion(nul_error)),
    }
}

pub(crate) fn c_char_pointer_to_string(c_char_p: *const raw::c_char) -> Result<String, Error> {
    let cs = unsafe { CStr::from_ptr(c_char_p) };
    match cs.to_str() {
        Ok(s) => Ok(String::from(s)),
        Err(e) => map_generic_error(GenericError::CCharConversion(e)),
    }
}

pub(crate) fn to_const_c_void<T>(v: &T) -> *const c_void {
    v as *const T as *const c_void
}

pub(crate) fn to_mut_c_void<T>(v: &mut T) -> *mut c_void {
    v as *mut T as *mut c_void
}

pub(crate) fn map_generic_error<T>(e: GenericError) -> Result<T, Error> {
    Err(Error::Generic(e))
}

pub(crate) fn map_libbpf_error<T>(function_name: &str, e: LibbpfError) -> Result<T, Error> {
    Err(Error::Libbpf(function_name.to_owned(), e))

}
pub(crate) fn map_libbpf_sys_error<T>(function_name: &str, e: i32) -> Result<T, Error> {
    Err(Error::Libbpf(function_name.to_owned(), LibbpfError::LibbpfSys(e)))
}
