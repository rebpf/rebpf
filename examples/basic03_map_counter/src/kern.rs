// This code is released under the
// General Public License (GPL), version 3
// http://www.gnu.org/licenses/gpl-3.0.en.html
// (c) Lorenzo Vannucci

mod common_kern_user;

use common_kern_user::{DataRec, MAX_ENTRIES};
use rebpf::{
    self,
    xdp::XdpAction,
    libbpf::xdp_md,
    LICENSE,
    VERSION,
    rebpf_macro::sec,
    BpfMapDef,
    BpfMapType,
    helpers
};
use std::sync::atomic::Ordering::Relaxed;

#[sec("license")]
pub static _license: [u8; 4] = LICENSE;

#[sec("version")]
pub static _version: u32 = VERSION;

#[sec("maps")]
pub static mut xdp_stats_map: BpfMapDef<u32, DataRec> = BpfMapDef::new(BpfMapType::ARRAY, MAX_ENTRIES);

#[sec("xdp_stats1")]
fn _xdp_stats1_func(ctx: *const _xdp_md) -> XdpAction {
    let key = XdpAction::PASS as u32;
    let r = helpers::bpf_map_lookup_elem(unsafe { &mut xdp_stats_map }, &key);
    if r.is_none() {
        return XdpAction::ABORTED;
    }
    let rec: &mut DataRec = r.unwrap();
    rec.rx_packets.fetch_add(1, Relaxed);
    
    XdpAction::PASS
}
