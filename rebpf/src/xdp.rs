use libbpf_sys as libbpf;
use std::ffi::{CString, CStr}; 
use libc;
use std::iter::FromIterator;
use std::path::Path;

use crate::{error::Error, BpfFd};

#[repr(u32)]
#[allow(non_camel_case_types)]
pub enum XdpFlags {
    UPDATE_IF_NOEXIST = libbpf::XDP_FLAGS_UPDATE_IF_NOEXIST,
    SKB_MODE = libbpf::XDP_FLAGS_SKB_MODE,
    DRV_MODE = libbpf::XDP_FLAGS_DRV_MODE,
    HW_MODE = libbpf::XDP_FLAGS_HW_MODE,
    MODES = libbpf::XDP_FLAGS_MODES,
    MASK = libbpf::XDP_FLAGS_MASK,
}

#[repr(u32)]
#[allow(non_camel_case_types)]
pub enum XdpAction {
    ABORTED = libbpf::XDP_ABORTED,
    DROP = libbpf::XDP_DROP,
    PASS = libbpf::XDP_PASS,
    TX = libbpf::XDP_TX,
    REDIRECT = libbpf::XDP_REDIRECT,
}


pub struct Interface {
    ifindex: u32
}

pub fn get_interface(dev: &str) -> Result<Interface, Error> {
    let ifindex = if_nametoindex(dev)?;
    Ok(Interface {
        ifindex
    })
}

pub fn bpf_set_link_xdp_fd(dev: &Interface, fd: &BpfFd, flags: &[XdpFlags]) -> Result<(), Error> {
    let flags = flags.iter().fold(0, |res, f| {
        return res | unsafe { *((f as *const XdpFlags) as *const u32) };
    });
    let err = unsafe {
        libbpf::bpf_set_link_xdp_fd(dev.ifindex as i32, fd.prog_fd, flags)
    };
    if err < 0 {
        return Err(Error::BpfSetLinkXdpFd(err));
    }
    
    Ok(())
}

fn if_nametoindex(dev: &str) -> Result<u32, Error> {
    let dev_cstring: CString = crate::str_to_cstring(dev)?;
    let ifindex = unsafe { libc::if_nametoindex(dev_cstring.as_ptr()) };
    if ifindex == 0 {
        Err(Error::InvalidInterfaceName)
    } else {
        Ok(ifindex)
    }
}
