use crate::{helpers::bpf_redirect_map, xdp::XdpAction, BpfMapDef, BpfMapType};

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

/// A map dedicated to redirecting packet processing to given CPUs, as
/// part of an XDP BPF program.
///
/// Example :
///
/// ```
/// use rebpf::maps::{CpuMap, Redirect};
/// use rebpf::xdp::{XdpAction, XdpMetadata};
/// use rebpf_macro::sec;
///
/// // Allocate a map to be able to dispatch traffic to the first 8 CPUs of the system.
/// #[sec("maps")]
/// pub static cpu_map: CpuMap = CpuMap::new(8);
///
/// #[sec("xdp_redirect_cpu")]
/// pub fn redirect_cpu(ctx: &XdpMetadata) -> XdpAction {
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
/// use rebpf::xdp::{XdpAction, XdpMetadata};
/// use rebpf_macro::sec;
///
/// // Allocate a single-slot map to host our only socket.
/// // The userspace application must then feed it with the socket FD.
/// #[sec("maps")]
/// pub static xsk_map: XskMap = XskMap::new(1);
///
/// #[sec("xdp_redirect_xsk")]
/// pub fn redirect_xsk(ctx: &XdpMetadata) -> XdpAction {
///     // Redirect all traffic to the only open socket
///     xsk_map.redirect(0)
/// }
/// ```
#[repr(transparent)]
pub struct XskMap(BpfMapDef<u32, i32>);

impl XskMap {
    pub const fn new(max_entries: u32) -> XskMap {
        XskMap(BpfMapDef::new(BpfMapType::CPUMAP, max_entries))
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
/// use rebpf::xdp::{XdpAction, XdpMetadata};
/// use rebpf_macro::sec;
///
/// // Allocate a single-slot map to host our port map.
/// // The userspace application must take care of setting the interface index
/// // of the target to the slot 0 of the map.
/// #[sec("maps")]
/// pub static dev_map: DevMap = DevMap::new(1);
///
/// #[sec("xdp_redirect_dev")]
/// pub fn redirect_dev(ctx: &XdpMetadata) -> XdpAction {
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
