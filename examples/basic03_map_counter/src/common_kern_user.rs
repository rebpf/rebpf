// This code is released under the
// General Public License (GPL), version 3
// http://www.gnu.org/licenses/gpl-3.0.en.html
// (c) Lorenzo Vannucci

use std::sync::atomic::AtomicU64;

#[repr(C)]
pub struct DataRec {
    pub rx_packets: AtomicU64
}

pub const MAX_ENTRIES: u32 = 5;
