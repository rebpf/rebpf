use crate::{
    helpers::{bpf_map_lookup_elem, bpf_redirect_map},
    libbpf::{XdpAction, BpfMapDef, BpfMapType},
};

/// This module contains type-safe abstractions around some of various maps that the BPF VM uses to
/// communicate with userspace. As the capabilities of the maps vary greatly, most of their
/// behaviour is exposed via specific traits.

/// This trait represents the ability for a map to specify an XDP redirection, whether to a network
/// device, a CPU, or a socket.
pub trait Redirect {
    fn redirect_or(&self, target: u32, default_action: XdpAction) -> XdpAction;
    fn redirect(&self, target: u32) -> XdpAction {
        self.redirect_or(target, XdpAction::ABORTED)
    }
}

/// This trait represents the ability to query a map for its content.
pub trait Lookup {
    type Key;
    type Value;
    /// Lookup the map content associated with the given key.
    ///
    /// # Safety
    ///
    /// The resulting reference is directly linked to the content of the map, which means
    /// it's the caller's job to ensure that there are no references to it elsewhere before
    /// playing around.
    ///
    /// CF https://prototype-kernel.readthedocs.io/en/latest/bpf/ebpf_maps.html#kernel-side-ebpf-program
    /// for reference.
    unsafe fn lookup_mut<'a>(&'a self, key: &Self::Key) -> Option<&'a mut Self::Value>;
}

/// A map dedicated to redirecting packet processing to given CPUs, as
/// part of an XDP BPF program.
///
/// Example :
///
/// ```
/// use rebpf::maps::{CpuMap, Redirect};
/// use rebpf::{XdpAction, XdpMd};
/// use rebpf_macro::sec;
///
/// // Allocate a map to be able to dispatch traffic to the first 8 CPUs of the system.
/// #[sec("maps")]
/// pub static cpu_map: CpuMap = CpuMap::new(8);
///
/// #[sec("xdp_redirect_cpu")]
/// pub fn redirect_cpu(ctx: &XdpMd) -> XdpAction {
///     // Redirect all traffic to the CPU 2
///     cpu_map.redirect(2)
/// }
/// ```
#[repr(transparent)]
pub struct CpuMap(BpfMapDef<u32, i32>);

impl CpuMap {
    pub const fn new(max_entries: u32) -> CpuMap {
        CpuMap(BpfMapDef::new(BpfMapType::CPUMAP, max_entries))
    }
}

impl Redirect for CpuMap {
    fn redirect_or(&self, target: u32, default_action: XdpAction) -> XdpAction {
        bpf_redirect_map(&self.0, &target, default_action)
    }
}

/// A map dedicated to redirecting packet processing to userspace AF_XDP sockets
/// as part of an XDP BPF program.
///
/// Example :
///
/// ```
/// use rebpf::maps::{XskMap, Redirect};
/// use rebpf::{XdpAction, XdpMd};
/// use rebpf_macro::sec;
///
/// // Allocate a single-slot map to host our only socket.
/// // The userspace application must then feed it with the socket FD.
/// #[sec("maps")]
/// pub static xsk_map: XskMap = XskMap::new(1);
///
/// #[sec("xdp_redirect_xsk")]
/// pub fn redirect_xsk(ctx: &XdpMd) -> XdpAction {
///     // Redirect all traffic to the only open socket
///     xsk_map.redirect(0)
/// }
/// ```
#[repr(transparent)]
pub struct XskMap(BpfMapDef<u32, i32>);

impl XskMap {
    pub const fn new(max_entries: u32) -> XskMap {
        XskMap(BpfMapDef::new(BpfMapType::XSKMAP, max_entries))
    }
}

impl Redirect for XskMap {
    fn redirect_or(&self, target: u32, default_action: XdpAction) -> XdpAction {
        bpf_redirect_map(&self.0, &target, default_action)
    }
}

/// A map dedicated to redirecting packet processing to other network devices
/// as part of an XDP BPF program.
///
/// Example :
///
/// ```
/// use rebpf::maps::{DevMap, Redirect};
/// use rebpf::{XdpAction, XdpMd};
/// use rebpf_macro::sec;
///
/// // Allocate a single-slot map to host our port map.
/// // The userspace application must take care of setting the interface index
/// // of the target to the slot 0 of the map.
/// #[sec("maps")]
/// pub static dev_map: DevMap = DevMap::new(1);
///
/// #[sec("xdp_redirect_dev")]
/// pub fn redirect_dev(ctx: &XdpMd) -> XdpAction {
///     // Redirect all traffic to the only open socket
///     dev_map.redirect(0)
/// }
/// ```
#[repr(transparent)]
pub struct DevMap(BpfMapDef<u32, i32>);

impl DevMap {
    pub const fn new(max_entries: u32) -> DevMap {
        DevMap(BpfMapDef::new(BpfMapType::CPUMAP, max_entries))
    }
}

impl Redirect for DevMap {
    fn redirect_or(&self, target: u32, default_action: XdpAction) -> XdpAction {
        bpf_redirect_map(&self.0, &target, default_action)
    }
}

/// A map dedicated to redirecting packet processing to other network devices
/// as part of an XDP BPF program.
///
/// Example :
///
/// ```
/// use rebpf::maps::{Array, Lookup};
/// use rebpf::{XdpAction, XdpMd};
/// use rebpf_macro::sec;
///
/// // Allocate a single-slot map to host our port map.
/// // The userspace application must take care of setting the interface index
/// // of the target to the slot 0 of the map.
/// #[sec("maps")]
/// pub static array: Array<u32> = Array::new(1);
///
/// #[sec("xdp_potential_drop")]
/// pub fn redirect_dev(ctx: &XdpMd) -> XdpAction {
///     // Redirect all traffic to the only open socket
///     let key = 0;
///     match unsafe { array.lookup_mut(&key) } {
///         Some(0) => XdpAction::DROP,
///         Some(_) => XdpAction::PASS,
///         None => XdpAction::ABORTED,
///     }
/// }
/// ```
#[repr(transparent)]
pub struct Array<T>(BpfMapDef<u32, T>);

impl<T> Array<T> {
    pub const fn new(max_entries: u32) -> Array<T> {
        Array(BpfMapDef::new(BpfMapType::ARRAY, max_entries))
    }
}

impl<T> Lookup for Array<T> {
    type Key = u32;
    type Value = T;
    unsafe fn lookup_mut<'a>(&'a self, key: &Self::Key) -> Option<&'a mut Self::Value> {
        bpf_map_lookup_elem(&self.0, key)
    }
}
