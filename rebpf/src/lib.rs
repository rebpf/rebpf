// This code is released under the
// GNU Lesser General Public License (LGPL), version 3
// https://www.gnu.org/licenses/lgpl-3.0.html
// (c) Lorenzo Vannucci

pub mod error;
pub mod helpers;
pub mod interface;
pub mod xdp;
pub use rebpf_macro;
pub use rebpf_sys::{bpf_sys, libbpf_sys as libbpf};

use error::Error;
use std::{
    ffi::{CStr, CString},
    marker::PhantomData,
    mem,
    os::raw,
    path::Path,
    ptr, vec,
};

pub const LICENSE: [u8; 4] = ['G' as u8, 'P' as u8, 'L' as u8, '\0' as u8]; //b"GPL\0"
pub const VERSION: u32 = 0xFFFFFFFE;

#[repr(u32)]
#[allow(non_camel_case_types)]
pub enum BpfProgType {
    UNSPEC = libbpf::bpf_prog_type_BPF_PROG_TYPE_UNSPEC,
    SOCKET_FILTER = libbpf::bpf_prog_type_BPF_PROG_TYPE_SOCKET_FILTER,
    KPROBE = libbpf::bpf_prog_type_BPF_PROG_TYPE_KPROBE,
    SCHED_CLS = libbpf::bpf_prog_type_BPF_PROG_TYPE_SCHED_CLS,
    SCHED_ACT = libbpf::bpf_prog_type_BPF_PROG_TYPE_SCHED_ACT,
    TRACEPOINT = libbpf::bpf_prog_type_BPF_PROG_TYPE_TRACEPOINT,
    XDP = libbpf::bpf_prog_type_BPF_PROG_TYPE_XDP,
    PERF_EVENT = libbpf::bpf_prog_type_BPF_PROG_TYPE_PERF_EVENT,
    CGROUP_SKB = libbpf::bpf_prog_type_BPF_PROG_TYPE_CGROUP_SKB,
    CGROUP_SOCK = libbpf::bpf_prog_type_BPF_PROG_TYPE_CGROUP_SOCK,
    LWT_IN = libbpf::bpf_prog_type_BPF_PROG_TYPE_LWT_IN,
    LWT_OUT = libbpf::bpf_prog_type_BPF_PROG_TYPE_LWT_OUT,
    LWT_XMIT = libbpf::bpf_prog_type_BPF_PROG_TYPE_LWT_XMIT,
    SOCK_OPS = libbpf::bpf_prog_type_BPF_PROG_TYPE_SOCK_OPS,
    SK_SKB = libbpf::bpf_prog_type_BPF_PROG_TYPE_SK_SKB,
    CGROUP_DEVICE = libbpf::bpf_prog_type_BPF_PROG_TYPE_CGROUP_DEVICE,
    SK_MSG = libbpf::bpf_prog_type_BPF_PROG_TYPE_SK_MSG,
    RAW_TRACEPOINT = libbpf::bpf_prog_type_BPF_PROG_TYPE_RAW_TRACEPOINT,
    CGROUP_SOCK_ADDR = libbpf::bpf_prog_type_BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
    LWT_SEG6LOCAL = libbpf::bpf_prog_type_BPF_PROG_TYPE_LWT_SEG6LOCAL,
    LIRC_MODE2 = libbpf::bpf_prog_type_BPF_PROG_TYPE_LIRC_MODE2,
    SK_REUSEPORT = libbpf::bpf_prog_type_BPF_PROG_TYPE_SK_REUSEPORT,
    FLOW_DISSECTOR = libbpf::bpf_prog_type_BPF_PROG_TYPE_FLOW_DISSECTOR,
    CGROUP_SYSCTL = libbpf::bpf_prog_type_BPF_PROG_TYPE_CGROUP_SYSCTL,
    RAW_TRACEPOINT_WRITABLE = libbpf::bpf_prog_type_BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE,
    CGROUP_SOCKOPT = libbpf::bpf_prog_type_BPF_PROG_TYPE_CGROUP_SOCKOPT,
}

#[repr(u32)]
#[allow(non_camel_case_types)]
pub enum BpfUpdateElemType {
    ANY = libbpf::BPF_ANY,
    NOEXIST = libbpf::BPF_NOEXIST,
    EXIST = libbpf::BPF_EXIST,
}

#[derive(Debug)]
#[repr(u32)]
#[allow(non_camel_case_types)]
pub enum BpfMapType {
    UNSPEC = libbpf::bpf_map_type_BPF_MAP_TYPE_UNSPEC,
    HASH = libbpf::bpf_map_type_BPF_MAP_TYPE_HASH,
    ARRAY = libbpf::bpf_map_type_BPF_MAP_TYPE_ARRAY,
    PROG_ARRAY = libbpf::bpf_map_type_BPF_MAP_TYPE_PROG_ARRAY,
    PERF_EVENT_ARRAY = libbpf::bpf_map_type_BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    PERCPU_HASH = libbpf::bpf_map_type_BPF_MAP_TYPE_PERCPU_HASH,
    PERCPU_ARRAY = libbpf::bpf_map_type_BPF_MAP_TYPE_PERCPU_ARRAY,
    STACK_TRACE = libbpf::bpf_map_type_BPF_MAP_TYPE_STACK_TRACE,
    CGROUP_ARRAY = libbpf::bpf_map_type_BPF_MAP_TYPE_CGROUP_ARRAY,
    LRU_HASH = libbpf::bpf_map_type_BPF_MAP_TYPE_LRU_HASH,
    LRU_PERCPU_HASH = libbpf::bpf_map_type_BPF_MAP_TYPE_LRU_PERCPU_HASH,
    LPM_TRIE = libbpf::bpf_map_type_BPF_MAP_TYPE_LPM_TRIE,
    ARRAY_OF_MAPS = libbpf::bpf_map_type_BPF_MAP_TYPE_ARRAY_OF_MAPS,
    HASH_OF_MAPS = libbpf::bpf_map_type_BPF_MAP_TYPE_HASH_OF_MAPS,
    DEVMAP = libbpf::bpf_map_type_BPF_MAP_TYPE_DEVMAP,
    SOCKMAP = libbpf::bpf_map_type_BPF_MAP_TYPE_SOCKMAP,
    CPUMAP = libbpf::bpf_map_type_BPF_MAP_TYPE_CPUMAP,
    XSKMAP = libbpf::bpf_map_type_BPF_MAP_TYPE_XSKMAP,
    SOCKHASH = libbpf::bpf_map_type_BPF_MAP_TYPE_SOCKHASH,
    CGROUP_STORAGE = libbpf::bpf_map_type_BPF_MAP_TYPE_CGROUP_STORAGE,
    REUSEPORT_SOCKARRAY = libbpf::bpf_map_type_BPF_MAP_TYPE_REUSEPORT_SOCKARRAY,
    PERCPU_CGROUP_STORAGE = libbpf::bpf_map_type_BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE,
    QUEUE = libbpf::bpf_map_type_BPF_MAP_TYPE_QUEUE,
    STACK = libbpf::bpf_map_type_BPF_MAP_TYPE_STACK,
    SK_STORAGE = libbpf::bpf_map_type_BPF_MAP_TYPE_SK_STORAGE,
    DEVMAP_HASH = libbpf::bpf_map_type_BPF_MAP_TYPE_DEVMAP_HASH,
}

pub struct BpfObject {
    pobj: *mut libbpf::bpf_object,
}

impl IntoIterator for &BpfObject {
    type Item = BpfProgram;
    type IntoIter = vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        let mut bpf_programs = Vec::new();
        let mut prog = bpf_program__next(None, self);
        while prog.is_some() {
            let prog2 = bpf_program__next(prog.as_ref(), self);
            bpf_programs.push(prog.unwrap());
            prog = prog2;
        }

        bpf_programs.into_iter()
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

pub type BpfProgFd = BpfFdImpl<BpfProgInfo, libbpf::bpf_prog_info>;

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
    pprogram: *mut libbpf::bpf_program,
}

pub struct BpfProgInfo {
    info: libbpf::bpf_prog_info,
}

impl BpfInfo for BpfProgInfo {
    type BpfRawInfoType = libbpf::bpf_prog_info;
    fn new(raw_info: Self::BpfRawInfoType) -> Self {
        BpfProgInfo { info: raw_info }
    }
}

impl BpfProgInfo {
    pub fn id(&self) -> u32 {
        self.info.id
    }

    pub fn name(&self) -> Result<String, Error> {
        let name = &self.info.name;
        c_char_pointer_to_string(name.as_ptr())
    }
}

pub struct BpfMap {
    pmap: *mut libbpf::bpf_map,
}

pub type UnsafeBpfMapFd = BpfFdImpl<BpfMapInfo, libbpf::bpf_map_info>;

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

pub struct BpfMapDef<T, U> {
    map_def: libbpf::bpf_map_def,
    _key_ty: PhantomData<T>,
    _value_ty: PhantomData<U>,
}

impl<T, U> BpfMapDef<T, U> {
    pub const fn new(type_: BpfMapType, max_entries: u32) -> Self {
        BpfMapDef {
            map_def: libbpf::bpf_map_def {
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
        let mut info: libbpf::bpf_map_info = unsafe { mem::zeroed() };
        info.type_ = self.map_def.type_;
        info.key_size = self.map_def.key_size;
        info.value_size = self.map_def.value_size;
        info.max_entries = self.map_def.max_entries;
        info.map_flags = self.map_def.map_flags;
        BpfMapInfo { info }
    }
}

pub struct BpfMapInfo {
    info: libbpf::bpf_map_info,
}

impl BpfInfo for BpfMapInfo {
    type BpfRawInfoType = libbpf::bpf_map_info;
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

pub fn bpf_obj_get_info_by_fd<T: BpfFd>(bpf_fd: &T) -> Result<T::BpfInfoType, Error>
where
    T::BpfInfoType: BpfInfo,
{
    let mut info: <<T as BpfFd>::BpfInfoType as BpfInfo>::BpfRawInfoType = unsafe { mem::zeroed() };
    let info_void_p = helpers::to_mut_c_void(&mut info);
    let mut info_len: u32 =
        mem::size_of::<<<T as BpfFd>::BpfInfoType as BpfInfo>::BpfRawInfoType>() as u32;
    let err = unsafe { libbpf::bpf_obj_get_info_by_fd(bpf_fd.fd(), info_void_p, &mut info_len) };
    if err != 0 {
        return Err(Error::BpfObjGetInfoByFd(err));
    }

    Ok(<<T as BpfFd>::BpfInfoType as BpfInfo>::new(info))
}

pub fn bpf_prog_load(
    file_path: &Path,
    bpf_prog_type: BpfProgType,
) -> Result<(BpfObject, BpfProgFd), Error> {
    let mut pobj: *mut libbpf::bpf_object = ptr::null_mut();
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
    let key_void_p = helpers::to_const_c_void(key);
    let value_void_p = helpers::to_mut_c_void(value);
    let err = unsafe { libbpf::bpf_map_lookup_elem(map_fd.fd(), key_void_p, value_void_p) };
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
    let bpf_program: *mut libbpf::bpf_program =
        unsafe { libbpf::bpf_object__find_program_by_title(bpf_object.pobj, title_cs.as_ptr()) };
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
        unsafe { libbpf::bpf_object__find_map_by_name(bpf_object.pobj, name_cs.as_ptr()) };
    if bpf_map.is_null() {
        return Ok(None);
    }
    Ok(Some(BpfMap { pmap: bpf_map }))
}

#[allow(non_snake_case)]
pub fn bpf_program__set_type(bpf_program: &mut BpfProgram, bpf_prog_type: BpfProgType) {
    unsafe {
        libbpf::bpf_program__set_type(bpf_program.pprogram, bpf_prog_type as u32);
    };
}

#[allow(non_snake_case)]
pub fn bpf_program__set_ifindex(bpf_program: &mut BpfProgram, interface: &interface::Interface) {
    unsafe {
        libbpf::bpf_program__set_ifindex(bpf_program.pprogram, interface.ifindex);
    };
}

#[allow(non_snake_case)]
pub fn bpf_program__next(
    bpf_program: Option<&BpfProgram>,
    bpf_object: &BpfObject,
) -> Option<BpfProgram> {
    let pprogram = unsafe {
        if bpf_program.is_some() {
            libbpf::bpf_program__next(bpf_program.unwrap().pprogram, bpf_object.pobj)
        } else {
            libbpf::bpf_program__next(ptr::null_mut(), bpf_object.pobj)
        }
    };
    if pprogram.is_null() {
        return None;
    }
    Some(BpfProgram { pprogram })
}

#[allow(non_snake_case)]
pub fn bpf_program__fd(bpf_program: &BpfProgram) -> Result<BpfProgFd, Error> {
    let prog_fd = unsafe { libbpf::bpf_program__fd(bpf_program.pprogram) };
    if prog_fd < 0 {
        return Err(Error::InvalidBpfProgram);
    }
    Ok(BpfProgFd {
        fd: prog_fd,
        _info_type: std::marker::PhantomData,
    })
}

#[allow(non_snake_case)]
pub fn bpf_program__title(bpf_program: &BpfProgram) -> Result<String, Error> {
    let title_c_char_p = unsafe { libbpf::bpf_program__title(bpf_program.pprogram, false) };
    if title_c_char_p.is_null() {
        return Err(Error::InvalidBpfProgram);
    }
    c_char_pointer_to_string(title_c_char_p)
}

#[allow(non_snake_case)]
pub fn bpf_map__fd<T, U>(bpf_map: &BpfMap) -> Result<BpfMapFd<T, U>, Error> {
    let fd = unsafe { libbpf::bpf_map__fd(bpf_map.pmap) };
    if fd < 0 {
        return Err(Error::InvalidBpfMap);
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

fn path_to_str(path: &Path) -> Result<&str, Error> {
    path.to_str().ok_or(Error::InvalidPath)
}

fn str_to_cstring(s: &str) -> Result<CString, Error> {
    let cstring_r = CString::new(s);
    match cstring_r {
        Ok(cstring) => Ok(cstring),
        Err(nul_error) => Err(Error::CStringConversion(nul_error)),
    }
}

fn c_char_pointer_to_string(c_char_p: *const raw::c_char) -> Result<String, Error> {
    let cs = unsafe { CStr::from_ptr(c_char_p) };
    match cs.to_str() {
        Ok(s) => Ok(String::from(s)),
        Err(e) => Err(Error::CCharConversion(e)),
    }
}
