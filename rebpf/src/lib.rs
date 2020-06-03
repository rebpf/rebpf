mod utils;

#[allow(unused)]
#[macro_use]
extern crate function_name;

pub use rebpf_macro;

pub mod error;
pub mod libbpf;
pub mod maps;

#[cfg(feature = "bpf")]
pub mod bpf;
#[cfg(feature = "bpf")]
pub mod helpers;

#[cfg(feature = "userspace")]
pub mod userspace;
#[cfg(feature = "userspace")]
pub mod interface;

pub const LICENSE: [u8; 4] = ['G' as u8, 'P' as u8, 'L' as u8, '\0' as u8]; //b"GPL\0"
pub const VERSION: u32 = 0xFFFFFFFE;
