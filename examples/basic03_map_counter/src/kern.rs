// This code is released under the
// General Public License (GPL), version 3
// http://www.gnu.org/licenses/gpl-3.0.en.html
// (c) Lorenzo Vannucci

mod common_kern_user;

use common_kern_user::{DataRec, MAX_ENTRIES};
use rebpf::{
    LICENSE,
    VERSION,
    rebpf_macro::sec,
    libbpf::{XdpAction, XdpMd},
    bpf::maps::{PerCpuArray, LookupMut},
};
//use pdu::*;
// use std::sync::atomic::Ordering::Relaxed;

#[sec("license")]
pub static _license: [u8; 4] = LICENSE;

#[sec("version")]
pub static _version: u32 = VERSION;

#[sec("maps")]
pub static xdp_stats_map: PerCpuArray<DataRec> = PerCpuArray::new(MAX_ENTRIES);
// pub static xdp_stats_map: Array<DataRec> = Array::new(MAX_ENTRIES);

#[sec("xdp_stats1")]
fn _xdp_stats1_func(_ctx: &XdpMd) -> XdpAction {
    let key = XdpAction::PASS as u32;
    // let rec = unsafe { xdp_stats_map.lookup_mut(&key) }.unwrap();
    let rec = match unsafe { xdp_stats_map.lookup_mut(&key) } {
        Some(rec) => { rec },
        None => { return XdpAction::ABORTED; },
    };

    // rec.rx_packets.fetch_add(1, Relaxed);
    rec.rx_packets += 1;
    // let packet = ctx.data_buffer();
    // match EthernetPdu::new(&packet) {
    //     Ok(ethernet_pdu) => {
    //         // upper-layer protocols can be accessed via the inner() method
    //         match ethernet_pdu.inner() {
    //             Ok(Ethernet::Ipv4(ipv4_pdu)) => {
    //                 rec.rx_ipv4_packets += 1;
    //                 rec.last_source_ipv4 = ipv4_pdu.source_address();
    //                 rec.last_dest_ipv4 = ipv4_pdu.destination_address();                    
    //             },
    //             Ok(Ethernet::Ipv6(_ipv6_pdu)) => {
    //                 rec.rx_ipv6_packets += 1;
    //             },
    //             _ => {},
    //         }
    //     },
    //     _ => {}
    // };
    XdpAction::PASS
}        
