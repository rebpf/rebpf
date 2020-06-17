// This code is released under the
// General Public License (GPL), version 3
// http://www.gnu.org/licenses/gpl-3.0.en.html
// (c) Lorenzo Vannucci

// use std::sync::atomic::AtomicU64;

//#[cfg_attr(feature = "userspace", derive(Default, Clone))]
#[derive(Default, Clone, Copy)]
#[repr(C)]
pub struct DataRec {
    pub packets_size: usize,
    pub rx_packets: u64,
    pub rx_ipv4_packets: u64,
    pub rx_ipv6_packets: u64,
    pub last_source_ipv4: [u8; 4],
    pub last_dest_ipv4: [u8; 4],
    pub last_source_mac: [u8; 6],
    pub last_dest_mac: [u8; 6],
 }

pub const MAX_ENTRIES: u32 = 5;
