use crate::{
    error::Result,
    helpers::{bpf_map_lookup_elem, bpf_redirect_map},
    libbpf::{BpfMapDef, BpfMapType, XdpAction},
    maps::*,
};

/// This module contains type-safe abstractions around some of various maps that the BPF VM uses to
/// communicate with userspace. As the capabilities of the maps vary greatly, most of their
/// behaviour is exposed via specific traits.

macro_rules! map_new {
    ($map_type:path: $type_const:expr) => {
        pub const fn new(max_entries: u32) -> $map_type {
            $map_type {
                def: BpfMapDef::new($type_const, max_entries),
            }
        }
    };
}

macro_rules! map_def {
    ($(#[$outer:meta])*
    struct $map_type:ident < $key:ty, $value:ty >: $type_const:expr) => {
        #[repr(transparent)]
        $(#[$outer])*
        pub struct $map_type<$key, $value> {
            def: BpfMapDef<$key, $value>,
        }
        impl<$key, $value> $map_type<$key, $value> { map_new! {$map_type<$key, $value>: $type_const} }
        impl<$key, $value> Map for $map_type<$key, $value> { type Key = $key; type Value = $value; }
    };
    ($(#[$outer:meta])*
    struct $map_type:ident < $value:ident >: $type_const:expr) => {
        #[repr(transparent)]
        $(#[$outer])*
        pub struct $map_type <$value> {
            def: BpfMapDef<u32, $value>,
        }
        impl<$value> $map_type<$value> { map_new! {$map_type<$value>: $type_const} }
        impl<$value> Map for $map_type<$value> { type Key = u32; type Value = $value; }
    };
    ($(#[$outer:meta])*
    struct $map_type:ident : $type_const:expr) => {
        #[repr(transparent)]
        $(#[$outer])*
        pub struct $map_type {
            def: BpfMapDef<u32, u32>,
        }
        impl $map_type { map_new! {$map_type: $type_const} }
        impl Map for $map_type { type Key = u32; type Value = u32; }
    };
}

/// This trait represents the ability for a map to specify an XDP redirection, whether to a network
/// device, a CPU, or a socket.
pub trait Redirect: Map {
    fn redirect_or(&self, target: Self::Key, default_action: XdpAction) -> XdpAction;
    fn redirect(&self, target: Self::Key) -> XdpAction {
        self.redirect_or(target, XdpAction::ABORTED)
    }
}

pub trait LookupMut: Map {
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

macro_rules! impl_map_redirect {
    ($map_def:ty) => {
        impl Redirect for $map_def {
            fn redirect_or(&self, target: u32, default_action: XdpAction) -> XdpAction {
                bpf_redirect_map(&self.def, &target, default_action)
            }
        }
    };
}

macro_rules! impl_map_lookup_mut {
    ($map_type:ident < $($gen:ident),* > ) => {
        impl<$($gen,)*> LookupMut for $map_type<$($gen,)*> {
            unsafe fn lookup_mut<'a>(&'a self, key: &Self::Key) -> Option<&'a mut Self::Value> {
                bpf_map_lookup_elem(&self.def, key)
            }
        }
    };
}

map_def! {
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
    struct CpuMap: BpfMapType::CPUMAP
}

impl_map_redirect!(CpuMap);

map_def! {
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
    struct XskMap: BpfMapType::XSKMAP
}
impl_map_redirect!(XskMap);

map_def! {
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
    struct DevMap: BpfMapType::DEVMAP
}
impl_map_redirect!(DevMap);

map_def! {
    /// A map behaving as a simple contiguous array, with arbitrary data as content.
    struct Array<T>: BpfMapType::ARRAY
}
impl_map_lookup_mut!(Array<T>);

map_def! {
    /// This map represent a faster array maintained on a per-CPU basis.
    struct PerCpuArray<T>: BpfMapType::PERCPU_ARRAY
}

impl_map_lookup_mut!(PerCpuArray<T>);
