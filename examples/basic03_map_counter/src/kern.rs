// This code is released under the
// General Public License (GPL), version 3
// http://www.gnu.org/licenses/gpl-3.0.en.html
// (c) Lorenzo Vannucci
mod common_kern_user;

use common_kern_user::{DataRec, MAX_ENTRIES};
use rebpf::{
    LICENSE,
    VERSION,
    rebpf_macro::{sec},
//    rebpf_macro::{sec, import_panic_symbol},
    libbpf::{XdpAction, XdpMd},
    bpf::maps::{PerCpuArray, LookupMut},
};
// use std::sync::atomic::Ordering::Relaxed;

#[sec("license")]
pub static _license: [u8; 4] = LICENSE;

#[sec("version")]
pub static _version: u32 = VERSION;

#[sec("maps")]
pub static xdp_stats_map: PerCpuArray<DataRec> = PerCpuArray::new(MAX_ENTRIES);
// pub static xdp_stats_map: Array<DataRec> = Array::new(MAX_ENTRIES);

//import_panic_symbol!();

#[sec("xdp_stats1")]
pub fn _xdp_stats1_func(_ctx: &XdpMd) -> XdpAction {
    let key = XdpAction::PASS as u32;
    let rec: &mut DataRec = match unsafe { xdp_stats_map.lookup_mut(&key) } {
        Some(rec) => { rec },
        None => { return XdpAction::ABORTED; },
    };

    // // rec.rx_packets.fetch_add(1, Relaxed);
    rec.rx_packets += 1;    
    let packet = if let Some(buffer) = _ctx.data_buffer() {
        buffer
    } else {
        return XdpAction::ABORTED;
    };
    rec.packets_size += packet.len();
    let packet_pointer = _ctx.data_pointer();
    let ethernet = pdu::EthernetPdu::new(packet, packet_pointer.1);
    let ethernet_pdu = if let Ok(ethernet_pdu) = ethernet {
        ethernet_pdu
    } else {
        return XdpAction::DROP;
    };
    rec.last_source_mac = ethernet_pdu.source_address();
    rec.last_dest_mac = ethernet_pdu.destination_address();
    let ipv4 = if let Ok(pdu::Ethernet::Ipv4(ipv4_pdu)) = ethernet_pdu.inner() {
        ipv4_pdu
    } else {
        return XdpAction::DROP;
    };
    rec.last_source_ipv4 = ipv4.source_address();
    rec.last_dest_ipv4 = ipv4.destination_address();
    
    XdpAction::PASS
}
