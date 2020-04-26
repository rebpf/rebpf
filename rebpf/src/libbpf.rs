use crate::{
    error::{Error, LibbpfError},
    interface,
    utils::*,
};
pub use libbpf_sys;
use std::{ffi::CString, marker::PhantomData, mem, os::raw, path::Path, ptr};

#[repr(u32)]
#[allow(non_camel_case_types)]
pub enum BpfProgType {
    UNSPEC = libbpf_sys::BPF_PROG_TYPE_UNSPEC,
    SOCKET_FILTER = libbpf_sys::BPF_PROG_TYPE_SOCKET_FILTER,
    KPROBE = libbpf_sys::BPF_PROG_TYPE_KPROBE,
    SCHED_CLS = libbpf_sys::BPF_PROG_TYPE_SCHED_CLS,
    SCHED_ACT = libbpf_sys::BPF_PROG_TYPE_SCHED_ACT,
    TRACEPOINT = libbpf_sys::BPF_PROG_TYPE_TRACEPOINT,
    XDP = libbpf_sys::BPF_PROG_TYPE_XDP,
    PERF_EVENT = libbpf_sys::BPF_PROG_TYPE_PERF_EVENT,
    CGROUP_SKB = libbpf_sys::BPF_PROG_TYPE_CGROUP_SKB,
    CGROUP_SOCK = libbpf_sys::BPF_PROG_TYPE_CGROUP_SOCK,
    LWT_IN = libbpf_sys::BPF_PROG_TYPE_LWT_IN,
    LWT_OUT = libbpf_sys::BPF_PROG_TYPE_LWT_OUT,
    LWT_XMIT = libbpf_sys::BPF_PROG_TYPE_LWT_XMIT,
    SOCK_OPS = libbpf_sys::BPF_PROG_TYPE_SOCK_OPS,
    SK_SKB = libbpf_sys::BPF_PROG_TYPE_SK_SKB,
    CGROUP_DEVICE = libbpf_sys::BPF_PROG_TYPE_CGROUP_DEVICE,
    SK_MSG = libbpf_sys::BPF_PROG_TYPE_SK_MSG,
    RAW_TRACEPOINT = libbpf_sys::BPF_PROG_TYPE_RAW_TRACEPOINT,
    CGROUP_SOCK_ADDR = libbpf_sys::BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
    LWT_SEG6LOCAL = libbpf_sys::BPF_PROG_TYPE_LWT_SEG6LOCAL,
    LIRC_MODE2 = libbpf_sys::BPF_PROG_TYPE_LIRC_MODE2,
    SK_REUSEPORT = libbpf_sys::BPF_PROG_TYPE_SK_REUSEPORT,
    FLOW_DISSECTOR = libbpf_sys::BPF_PROG_TYPE_FLOW_DISSECTOR,
    CGROUP_SYSCTL = libbpf_sys::BPF_PROG_TYPE_CGROUP_SYSCTL,
    RAW_TRACEPOINT_WRITABLE = libbpf_sys::BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE,
    CGROUP_SOCKOPT = libbpf_sys::BPF_PROG_TYPE_CGROUP_SOCKOPT,
}

bitflags::bitflags! {
    pub struct BpfUpdateElemFlags: u32 {
        const ANY = libbpf_sys::BPF_ANY;
        const NOEXIST = libbpf_sys::BPF_NOEXIST;
        const EXIST = libbpf_sys::BPF_EXIST;
    }
}

#[derive(Debug)]
#[repr(u32)]
#[allow(non_camel_case_types)]
pub enum BpfMapType {
    UNSPEC = libbpf_sys::BPF_MAP_TYPE_UNSPEC,
    HASH = libbpf_sys::BPF_MAP_TYPE_HASH,
    ARRAY = libbpf_sys::BPF_MAP_TYPE_ARRAY,
    PROG_ARRAY = libbpf_sys::BPF_MAP_TYPE_PROG_ARRAY,
    PERF_EVENT_ARRAY = libbpf_sys::BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    PERCPU_HASH = libbpf_sys::BPF_MAP_TYPE_PERCPU_HASH,
    PERCPU_ARRAY = libbpf_sys::BPF_MAP_TYPE_PERCPU_ARRAY,
    STACK_TRACE = libbpf_sys::BPF_MAP_TYPE_STACK_TRACE,
    CGROUP_ARRAY = libbpf_sys::BPF_MAP_TYPE_CGROUP_ARRAY,
    LRU_HASH = libbpf_sys::BPF_MAP_TYPE_LRU_HASH,
    LRU_PERCPU_HASH = libbpf_sys::BPF_MAP_TYPE_LRU_PERCPU_HASH,
    LPM_TRIE = libbpf_sys::BPF_MAP_TYPE_LPM_TRIE,
    ARRAY_OF_MAPS = libbpf_sys::BPF_MAP_TYPE_ARRAY_OF_MAPS,
    HASH_OF_MAPS = libbpf_sys::BPF_MAP_TYPE_HASH_OF_MAPS,
    DEVMAP = libbpf_sys::BPF_MAP_TYPE_DEVMAP,
    SOCKMAP = libbpf_sys::BPF_MAP_TYPE_SOCKMAP,
    CPUMAP = libbpf_sys::BPF_MAP_TYPE_CPUMAP,
    XSKMAP = libbpf_sys::BPF_MAP_TYPE_XSKMAP,
    SOCKHASH = libbpf_sys::BPF_MAP_TYPE_SOCKHASH,
    CGROUP_STORAGE = libbpf_sys::BPF_MAP_TYPE_CGROUP_STORAGE,
    REUSEPORT_SOCKARRAY = libbpf_sys::BPF_MAP_TYPE_REUSEPORT_SOCKARRAY,
    PERCPU_CGROUP_STORAGE = libbpf_sys::BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE,
    QUEUE = libbpf_sys::BPF_MAP_TYPE_QUEUE,
    STACK = libbpf_sys::BPF_MAP_TYPE_STACK,
    SK_STORAGE = libbpf_sys::BPF_MAP_TYPE_SK_STORAGE,
    DEVMAP_HASH = libbpf_sys::BPF_MAP_TYPE_DEVMAP_HASH,
}

pub struct BpfObject {
    pobj: *mut libbpf_sys::bpf_object,
}

pub struct BpfObjectIterator<'a> {
    src: &'a BpfObject,
    next: Option<BpfProgram>,
}

impl BpfObjectIterator<'_> {
    fn new(src: &BpfObject) -> BpfObjectIterator {
        let next = bpf_program__next(None, src);
        BpfObjectIterator { src, next }
    }
}

impl Iterator for BpfObjectIterator<'_> {
    type Item = BpfProgram;

    fn next(&mut self) -> Option<Self::Item> {
        match &self.next {
            Some(prog) => {
                let mut next = bpf_program__next(Some(prog), self.src);
                mem::swap(&mut next, &mut self.next);
                next
            }
            None => None,
        }
    }
}

impl<'a> IntoIterator for &'a BpfObject {
    type Item = BpfProgram;
    type IntoIter = BpfObjectIterator<'a>;

    fn into_iter(self) -> Self::IntoIter {
        BpfObjectIterator::new(self)
    }
}

pub trait BpfFd {
    type BpfInfoType;
    fn fd(&self) -> raw::c_int;
}

pub trait BpfInfo {
    type BpfRawInfoType;
    fn new(raw_info: Self::BpfRawInfoType) -> Self;
}

pub type BpfProgFd = BpfFdImpl<BpfProgInfo, libbpf_sys::bpf_prog_info>;

pub struct BpfFdImpl<T, U>
where
    T: BpfInfo<BpfRawInfoType = U>,
{
    fd: raw::c_int,
    _info_type: std::marker::PhantomData<T>,
}

impl<T, U> BpfFd for BpfFdImpl<T, U>
where
    T: BpfInfo<BpfRawInfoType = U>,
{
    type BpfInfoType = T;

    fn fd(&self) -> raw::c_int {
        self.fd
    }
}

pub struct BpfProgram {
    pprogram: *mut libbpf_sys::bpf_program,
}

pub struct BpfProgInfo {
    info: libbpf_sys::bpf_prog_info,
}

impl BpfInfo for BpfProgInfo {
    type BpfRawInfoType = libbpf_sys::bpf_prog_info;
    fn new(raw_info: Self::BpfRawInfoType) -> Self {
        BpfProgInfo { info: raw_info }
    }
}

impl BpfProgInfo {
    pub fn id(&self) -> u32 {
        self.info.id
    }

    #[named]
    pub fn name(&self) -> Result<String, Error> {
        let name = &self.info.name;
        c_char_pointer_to_string(name.as_ptr())
    }
}

pub struct BpfMap {
    pmap: *mut libbpf_sys::bpf_map,
}

pub type UnsafeBpfMapFd = BpfFdImpl<BpfMapInfo, libbpf_sys::bpf_map_info>;

pub struct BpfMapFd<T, U> {
    map_fd: UnsafeBpfMapFd,
    _key_ty: std::marker::PhantomData<T>,
    _value_ty: std::marker::PhantomData<U>,
}

impl<T, U> BpfFd for BpfMapFd<T, U> {
    type BpfInfoType = BpfMapInfo;
    fn fd(&self) -> raw::c_int {
        self.map_fd.fd()
    }
}

#[repr(transparent)]
pub struct BpfMapDef<T, U> {
    pub(crate) map_def: libbpf_sys::bpf_map_def,
    _key_ty: PhantomData<T>,
    _value_ty: PhantomData<U>,
}

impl<T, U> BpfMapDef<T, U> {
    pub const fn new(type_: BpfMapType, max_entries: u32) -> Self {
        BpfMapDef {
            map_def: libbpf_sys::bpf_map_def {
                type_: type_ as u32,
                key_size: mem::size_of::<T>() as u32,
                value_size: mem::size_of::<U>() as u32,
                max_entries,
                map_flags: 0,
            },
            _key_ty: PhantomData,
            _value_ty: PhantomData,
        }
    }

    pub fn to_bpf_map_info(&self) -> BpfMapInfo {
        let mut info: libbpf_sys::bpf_map_info = unsafe { mem::zeroed() };
        info.type_ = self.map_def.type_;
        info.key_size = self.map_def.key_size;
        info.value_size = self.map_def.value_size;
        info.max_entries = self.map_def.max_entries;
        info.map_flags = self.map_def.map_flags;
        BpfMapInfo { info }
    }
}

pub struct BpfMapInfo {
    info: libbpf_sys::bpf_map_info,
}

impl BpfInfo for BpfMapInfo {
    type BpfRawInfoType = libbpf_sys::bpf_map_info;
    fn new(raw_info: Self::BpfRawInfoType) -> Self {
        BpfMapInfo { info: raw_info }
    }
}

impl BpfMapInfo {
    pub fn id(&self) -> u32 {
        self.info.id
    }
    pub fn value_size(&self) -> u32 {
        self.info.value_size
    }
    pub fn key_size(&self) -> u32 {
        self.info.key_size
    }
    pub fn max_entries(&self) -> u32 {
        self.info.max_entries
    }
    pub fn type_(&self) -> BpfMapType {
        let map_type: BpfMapType = unsafe { std::mem::transmute(self.info.type_) };
        map_type
    }

    pub fn name(&self) -> Result<String, Error> {
        let name = &self.info.name;
        c_char_pointer_to_string(name.as_ptr())
    }
}

#[named]
pub fn bpf_obj_get_info_by_fd<T: BpfFd>(bpf_fd: &T) -> Result<T::BpfInfoType, Error>
where
    T::BpfInfoType: BpfInfo,
{
    let mut info: <<T as BpfFd>::BpfInfoType as BpfInfo>::BpfRawInfoType = unsafe { mem::zeroed() };
    let info_void_p = to_mut_c_void(&mut info);
    let mut info_len: u32 =
        mem::size_of::<<<T as BpfFd>::BpfInfoType as BpfInfo>::BpfRawInfoType>() as u32;
    let err = unsafe { libbpf_sys::bpf_obj_get_info_by_fd(bpf_fd.fd(), info_void_p, &mut info_len) };
    if err != 0 {
        return map_libbpf_error(function_name!(), LibbpfError::LibbpfSys(err));
    }

    Ok(<<T as BpfFd>::BpfInfoType as BpfInfo>::new(info))
}

#[named]
pub fn bpf_prog_load(
    file_path: &Path,
    bpf_prog_type: BpfProgType,
) -> Result<(BpfObject, BpfProgFd), Error> {
    let mut pobj: *mut libbpf_sys::bpf_object = ptr::null_mut();
    let mut prog_fd: raw::c_int = -1;

    let file_path_s = path_to_str(file_path)?;
    let file = str_to_cstring(file_path_s)?;
    let err = unsafe {
        libbpf_sys::bpf_prog_load(file.as_ptr(), bpf_prog_type as u32, &mut pobj, &mut prog_fd)
    };
    if err != 0 {
        return map_libbpf_error(function_name!(), LibbpfError::LibbpfSys(err));
    }
    if prog_fd < 0 {
        return map_libbpf_error(function_name!(), LibbpfError::InvalidFd);
    }

    Ok((
        BpfObject { pobj },
        BpfProgFd {
            fd: prog_fd,
            _info_type: std::marker::PhantomData,
        },
    ))
}

#[allow(non_snake_case)]
pub fn bpf_map_lookup_elem<T, U>(map_fd: &BpfMapFd<T, U>, key: &T, value: &mut U) -> Option<()> {
    let key_void_p = to_const_c_void(key);
    let value_void_p = to_mut_c_void(value);
    let err = unsafe { libbpf_sys::bpf_map_lookup_elem(map_fd.fd(), key_void_p, value_void_p) };
    if err != 0 {
        return None;
    }
    Some(())
}

#[allow(non_snake_case)]
pub fn bpf_object__find_program_by_title(
    bpf_object: &BpfObject,
    title: &str,
) -> Result<Option<BpfProgram>, Error> {
    let title_cs: CString = str_to_cstring(title)?;
    let bpf_program: *mut libbpf_sys::bpf_program =
        unsafe { libbpf_sys::bpf_object__find_program_by_title(bpf_object.pobj, title_cs.as_ptr()) };
    if bpf_program.is_null() {
        return Ok(None);
    }
    Ok(Some(BpfProgram {
        pprogram: bpf_program,
    }))
}

#[allow(non_snake_case)]
pub fn bpf_object__find_map_by_name(
    bpf_object: &BpfObject,
    name: &str,
) -> Result<Option<BpfMap>, Error> {
    let name_cs = str_to_cstring(name)?;
    let bpf_map =
        unsafe { libbpf_sys::bpf_object__find_map_by_name(bpf_object.pobj, name_cs.as_ptr()) };
    if bpf_map.is_null() {
        return Ok(None);
    }
    Ok(Some(BpfMap { pmap: bpf_map }))
}

#[allow(non_snake_case)]
pub fn bpf_program__set_type(bpf_program: &mut BpfProgram, bpf_prog_type: BpfProgType) {
    unsafe {
        libbpf_sys::bpf_program__set_type(bpf_program.pprogram, bpf_prog_type as u32);
    };
}

#[allow(non_snake_case)]
pub fn bpf_program__set_ifindex(bpf_program: &mut BpfProgram, interface: &interface::Interface) {
    unsafe {
        libbpf_sys::bpf_program__set_ifindex(bpf_program.pprogram, interface.ifindex);
    };
}

#[allow(non_snake_case)]
pub fn bpf_program__next(
    bpf_program: Option<&BpfProgram>,
    bpf_object: &BpfObject,
) -> Option<BpfProgram> {
    let pprogram = unsafe {
        libbpf_sys::bpf_program__next(
            bpf_program.map(|p| p.pprogram).unwrap_or(ptr::null_mut()),
            bpf_object.pobj,
        )
    };
    if pprogram.is_null() {
        return None;
    }
    Some(BpfProgram { pprogram })
}

#[allow(non_snake_case)]
#[named]
pub fn bpf_program__fd(bpf_program: &BpfProgram) -> Result<BpfProgFd, Error> {
    let prog_fd = unsafe { libbpf_sys::bpf_program__fd(bpf_program.pprogram) };
    if prog_fd < 0 {
        return map_libbpf_error(function_name!(), LibbpfError::InvalidFd);
    }
    Ok(BpfProgFd {
        fd: prog_fd,
        _info_type: std::marker::PhantomData,
    })
}

#[allow(non_snake_case)]
#[named]
pub fn bpf_program__title(bpf_program: &BpfProgram) -> Result<String, Error> {
    let title_c_char_p = unsafe { libbpf_sys::bpf_program__title(bpf_program.pprogram, false) };
    if title_c_char_p.is_null() {
        return map_libbpf_error(function_name!(), LibbpfError::InvalidTitle);
    }
    c_char_pointer_to_string(title_c_char_p)
}

#[allow(non_snake_case)]
#[named]
pub fn bpf_map__fd<T, U>(bpf_map: &BpfMap) -> Result<BpfMapFd<T, U>, Error> {
    let fd = unsafe { libbpf_sys::bpf_map__fd(bpf_map.pmap) };
    if fd < 0 {
        return map_libbpf_error(function_name!(), LibbpfError::InvalidFd);
    }
    Ok(BpfMapFd {
        map_fd: UnsafeBpfMapFd {
            fd,
            _info_type: std::marker::PhantomData,
        },
        _key_ty: std::marker::PhantomData,
        _value_ty: std::marker::PhantomData,
    })
}

#[derive(Debug)]
#[repr(u32)]
#[allow(non_camel_case_types)]
pub enum XdpAction {
    ABORTED = libbpf_sys::XDP_ABORTED,
    DROP = libbpf_sys::XDP_DROP,
    PASS = libbpf_sys::XDP_PASS,
    TX = libbpf_sys::XDP_TX,
    REDIRECT = libbpf_sys::XDP_REDIRECT,
}

bitflags::bitflags! {
    pub struct XdpFlags: u32 {
        const UPDATE_IF_NOEXIST = libbpf_sys::XDP_FLAGS_UPDATE_IF_NOEXIST;
        const SKB_MODE = libbpf_sys::XDP_FLAGS_SKB_MODE;
        const DRV_MODE = libbpf_sys::XDP_FLAGS_DRV_MODE;
        const HW_MODE = libbpf_sys::XDP_FLAGS_HW_MODE;
        const MODES = libbpf_sys::XDP_FLAGS_MODES;
        const MASK = libbpf_sys::XDP_FLAGS_MASK;
    }
}

#[repr(transparent)]
pub struct XdpMd(libbpf_sys::xdp_md);

impl XdpMd {
    pub fn data_buffer(&self) -> &[u8] {
        unsafe {
            let data_64 = self.0.data as u64;
            let data_buffer: *const u8 = std::mem::transmute(data_64);
            let data_buffer_size = (self.0.data_end - self.0.data) as usize;
            std::slice::from_raw_parts(data_buffer, data_buffer_size)
        }
    }
    pub fn data_meta(&self) -> u32 {
        self.0.data_meta
    }
    pub fn ingress_ifindex(&self) -> u32 {
        self.0.ingress_ifindex
    }
    pub fn rx_queue_index(&self) -> u32 {
        self.0.rx_queue_index
    }
}

#[named]
pub fn bpf_set_link_xdp_fd(
    interface: &interface::Interface,
    bpf_fd: Option<&BpfProgFd>,
    xdp_flags: XdpFlags,
) -> Result<(), Error> {
    let err = unsafe {
        if bpf_fd.is_some() {
            let bpf_fd = bpf_fd.unwrap();
            libbpf_sys::bpf_set_link_xdp_fd(interface.ifindex as i32, bpf_fd.fd, xdp_flags.bits())
        } else {
            libbpf_sys::bpf_set_link_xdp_fd(interface.ifindex as i32, -1, xdp_flags.bits())
        }
    };
    if err < 0 {
        return map_libbpf_error(function_name!(), LibbpfError::LibbpfSys(err));
    }

    Ok(())
}
