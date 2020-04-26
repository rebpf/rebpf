mod utils;

#[macro_use]
extern crate function_name;

pub use rebpf_macro;
pub mod error;
pub mod interface;
pub mod libbpf;
pub mod helpers;
pub mod bpf;
//pub mod userspace;

pub const LICENSE: [u8; 4] = ['G' as u8, 'P' as u8, 'L' as u8, '\0' as u8]; //b"GPL\0"
pub const VERSION: u32 = 0xFFFFFFFE;
