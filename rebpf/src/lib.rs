pub mod xdp;
pub mod error;
pub use libbpf_sys as libbpf;
pub use rebpf_macro;

use std::os::raw;

use std::path::Path;
use std::ffi::{CString, CStr};
use error::Error;


pub const LICENSE: [u8; 4] = ['G' as u8, 'P' as u8, 'L' as u8, '\0' as u8]; //b"GPL\0"
pub const VERSION: u32 = 0xFFFFFFFE;

#[repr(u32)]
#[allow(non_camel_case_types)]
pub enum BpfProgType {
    UNSPEC = libbpf::BPF_PROG_TYPE_UNSPEC,
    FILTER = libbpf::BPF_PROG_TYPE_SOCKET_FILTER,
    KPROBE =  libbpf::BPF_PROG_TYPE_KPROBE,
    SCHED_CLS = libbpf::BPF_PROG_TYPE_SCHED_CLS,
    SCHED_ACT = libbpf::BPF_PROG_TYPE_SCHED_ACT,
    TRACEPOINT = libbpf::BPF_PROG_TYPE_TRACEPOINT,
    XDP = libbpf::BPF_PROG_TYPE_XDP,
    PERF_EVENT = libbpf::BPF_PROG_TYPE_PERF_EVENT,
    CGROUP_SKB = libbpf::BPF_PROG_TYPE_CGROUP_SKB,
    CGROUP_SOCK = libbpf::BPF_PROG_TYPE_CGROUP_SOCK,
    LWT_IN = libbpf::BPF_PROG_TYPE_LWT_IN,
    LWT_OUT = libbpf::BPF_PROG_TYPE_LWT_OUT,
    LWT_XMIT = libbpf::BPF_PROG_TYPE_LWT_XMIT,
    SOCK_OPS = libbpf::BPF_PROG_TYPE_SOCK_OPS,
    SK_SKB = libbpf::BPF_PROG_TYPE_SK_SKB,
    CGROUP_DEVICE = libbpf::BPF_PROG_TYPE_CGROUP_DEVICE,
    SK_MSG = libbpf::BPF_PROG_TYPE_SK_MSG,
    RAW_TRACEPOINT = libbpf::BPF_PROG_TYPE_RAW_TRACEPOINT,
    CGROUP_SOCK_ADDR = libbpf::BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
    LWT_SEG6LOCAL = libbpf::BPF_PROG_TYPE_LWT_SEG6LOCAL,
    LIRC_MODE2 = libbpf::BPF_PROG_TYPE_LIRC_MODE2,
    SK_REUSEPORT = libbpf::BPF_PROG_TYPE_SK_REUSEPORT,
    FLOW_DISSECTOR = libbpf::BPF_PROG_TYPE_FLOW_DISSECTOR,
    CGROUP_SYSCTL = libbpf::BPF_PROG_TYPE_CGROUP_SYSCTL,
    RAW_TRACEPOINT_WRITABLE = libbpf::BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE,
    CGROUP_SOCKOPT = libbpf::BPF_PROG_TYPE_CGROUP_SOCKOPT,
    TRACING = libbpf::BPF_PROG_TYPE_TRACING,
}

pub struct BpfObject {
    pobj: *const libbpf::bpf_object
}

pub struct BpfFd {
    prog_fd: raw::c_int
}

pub struct BpfProg {
    pub bpf_object: BpfObject,
    pub bpf_fd: BpfFd
}

pub struct BpfProgInfo {
    info: libbpf::bpf_prog_info,
    info_len: u32
}

impl BpfProgInfo {
    pub fn get_id(&self) -> u32 {
        return self.info.id;
    }

    pub fn get_name(&self) -> String {
        let name = &self.info.name[0..];
        let s = unsafe { CStr::from_ptr(name.as_ptr()) };
        String::from(s.to_str().unwrap())
    }
}

pub fn bpf_obj_get_info_by_fd(bpf_fd: &BpfFd) -> Result<BpfProgInfo, Error> {
    let mut info: libbpf::bpf_prog_info = unsafe { std::mem::zeroed() };
    let info_void_p = (&mut info as *mut libbpf::bpf_prog_info) as *mut raw::c_void;
    let mut info_len: u32 = 0;
    let err = unsafe {
        libbpf::bpf_obj_get_info_by_fd(bpf_fd.prog_fd, info_void_p, &mut info_len)
    };
    if err != 0 {
        return Err(Error::BpfObjGetInfoByFd(err));
    }
    
    Ok(BpfProgInfo {
        info,
        info_len
    })
}

pub fn bpf_prog_load(file_path: &Path, bpf_prog_type: BpfProgType) -> Result<BpfProg, Error> {
    let mut pobj: *mut libbpf::bpf_object = unsafe { std::mem::zeroed() };
    let mut prog_fd: raw::c_int = -1;

    let file_path_s = path_to_str(file_path)?;
    let file = str_to_cstring(file_path_s)?;
    let err = unsafe {
        libbpf::bpf_prog_load(file.as_ptr(), bpf_prog_type as u32, &mut pobj, &mut prog_fd)
    };
    if err != 0 {
        return Err(Error::BpfProgLoad(err));
    }
    if prog_fd < 0 {
        return Err(Error::InvalidPath);
    }

    Ok(BpfProg {
        bpf_object: BpfObject { pobj },
        bpf_fd: BpfFd { prog_fd }
    })
}

fn path_to_str(path: &Path) -> Result<&str, Error> {
    path.to_str().ok_or(Error::InvalidPath)
}

fn str_to_cstring(s: &str) -> Result<CString, Error> {
    let cstring_r = CString::new(s);
    match cstring_r {
        Ok(cstring) => Ok(cstring),
        Err(nul_error) => Err(Error::CStringConversion(nul_error))
    }
}
