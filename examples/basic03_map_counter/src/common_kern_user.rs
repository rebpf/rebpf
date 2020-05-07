// This code is released under the
// General Public License (GPL), version 3
// http://www.gnu.org/licenses/gpl-3.0.en.html
// (c) Lorenzo Vannucci

// use std::sync::atomic::AtomicU64;

#[derive(Default, Clone)]
#[repr(C)]
pub struct DataRec {
    pub rx_packets: u64,
    pub rx_ipv4_packets: u64,
    pub rx_ipv6_packets: u64,
    pub last_source_ipv4: [u8; 4],
    pub last_dest_ipv4: [u8; 4],
}

pub const MAX_ENTRIES: u32 = 5;
