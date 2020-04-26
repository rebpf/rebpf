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
    bpf::maps::{Array, Lookup},
};
use std::sync::atomic::Ordering::Relaxed;

#[sec("license")]
pub static _license: [u8; 4] = LICENSE;

#[sec("version")]
pub static _version: u32 = VERSION;

#[sec("maps")]
pub static xdp_stats_map: Array<DataRec> = Array::new(MAX_ENTRIES);

#[sec("xdp_stats1")]
fn _xdp_stats1_func(_ctx: &XdpMd) -> XdpAction {
    let key = XdpAction::PASS as u32;
    match unsafe { xdp_stats_map.lookup_mut(&key) } {
        Some(rec) => {
            rec.rx_packets.fetch_add(1, Relaxed);
            XdpAction::PASS
        }
        None => XdpAction::ABORTED,
    }
}
