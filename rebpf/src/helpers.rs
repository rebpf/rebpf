// This code is released under the
// GNU Lesser General Public License (LGPL), version 3
// https://www.gnu.org/licenses/lgpl-3.0.html
// (c) Lorenzo Vannucci

use crate::{error::Error, xdp::XdpAction, BpfMapDef, BpfUpdateElemType};
use rebpf_sys::libbpf_sys as libbpf;
use crate::{BpfMapDef, BpfUpdateElemType, error::Error, xdp::XdpAction};
use std::{
    mem,
    option::Option,
    os::raw::{c_int, c_void},
};

pub fn bpf_map_lookup_elem<'a, 'b, T, U>(map: &'a BpfMapDef<T, U>, key: &'b T) -> Option<&'a mut U> {
    type FPtrType = extern "C" fn(m: *const c_void, k: *const c_void) -> *mut c_void;
    unsafe {
        let f: FPtrType = mem::transmute(libbpf::bpf_func_id_BPF_FUNC_map_lookup_elem as usize);
        let value = f(to_const_c_void(&map.map_def), to_const_c_void(key));
        if value.is_null() {
            None
        } else {
            Some(&mut *(value as *mut U))
        }
    }
}

pub fn bpf_map_update_elem<'a, 'b, T, U>(
    map: &'a mut BpfMapDef<T, U>,
    key: &'b T,
    value: &'a U,
    flags: BpfUpdateElemType,
) -> Result<(), Error> {
    type FPtrType =
        extern "C" fn(m: *mut c_void, k: *const c_void, v: *const c_void, f: u64) -> c_int;
    let r = unsafe {
        let f: FPtrType = mem::transmute(libbpf::bpf_func_id_BPF_FUNC_map_update_elem as usize);
        f(
            to_mut_c_void(&mut map.map_def),
            to_const_c_void(key),
            to_const_c_void(value),
            flags as u64,
        )
    };
    if r < 0 {
        return Err(Error::BpfMapUpdateElem(r));
    }
    Ok(())
}

/// This function is a very thin wrapper around the built-in bpf_redirect_map.
///
/// See the [kernel documentation](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/uapi/linux/bpf.h#n1626)
/// for more details.
pub fn bpf_redirect_map<'a, 'b, U>(
    map: &'a BpfMapDef<u32, U>,
    key: &'b u32,
    default_action: XdpAction,
) -> XdpAction {
    let flags: u32 = default_action as u32;
    if flags > XdpAction::TX as u32 {
        // We panic here because this is a programming error, not something
        // that would occur during a normal execution.
        panic!("The default action must be one of ABORTED, DROP, PASS or TX");
    }

    type FPtrType = extern "C" fn(m: *const c_void, k: *const c_void, f: u64) -> c_int;
    unsafe {
        let f: FPtrType = mem::transmute(libbpf::bpf_func_id_BPF_FUNC_redirect_map as usize);
        let r = f(
            to_const_c_void(&map.map_def),
            to_const_c_void(key),
            flags as u64,
        );
        mem::transmute::<i32, XdpAction>(r)
    }
}

pub(crate) fn to_const_c_void<T>(v: &T) -> *const c_void {
    v as *const T as *const c_void
}

pub(crate) fn to_mut_c_void<T>(v: &mut T) -> *mut c_void {
    v as *mut T as *mut c_void
}
