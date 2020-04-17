// This code is released under the
// GNU Lesser General Public License (LGPL), version 3
// https://www.gnu.org/licenses/lgpl-3.0.html
// (c) Lorenzo Vannucci

use rebpf_sys::libbpf_sys as libbpf;

use crate::{interface::Interface, error::Error, BpfProgFd};

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

#[derive(Debug)]
#[repr(u32)]
#[allow(non_camel_case_types)]
pub enum XdpAction {
    ABORTED = libbpf::xdp_action_XDP_ABORTED,
    DROP = libbpf::xdp_action_XDP_DROP,
    PASS = libbpf::xdp_action_XDP_PASS,
    TX = libbpf::xdp_action_XDP_TX,
    REDIRECT = libbpf::xdp_action_XDP_REDIRECT,
}

#[repr(transparent)]
pub struct XdpMetadata(libbpf::xdp_md);

pub fn bpf_set_link_xdp_fd(interface: &Interface, bpf_fd: Option<&BpfProgFd>, xdp_flags: &[XdpFlags]) -> Result<(), Error> {
    let xdp_flags = xdp_flags.iter().fold(0, |res, f| {
        return res | unsafe { *((f as *const XdpFlags) as *const u32) };
    });
    let err = unsafe {
        if bpf_fd.is_some() {
            let bpf_fd = bpf_fd.unwrap();
            libbpf::bpf_set_link_xdp_fd(interface.ifindex as i32, bpf_fd.fd, xdp_flags)
        } else {
            libbpf::bpf_set_link_xdp_fd(interface.ifindex as i32, -1, xdp_flags)
        }
    };
    if err < 0 {
        return Err(Error::BpfSetLinkXdpFd(err));
    }
    
    Ok(())
}

