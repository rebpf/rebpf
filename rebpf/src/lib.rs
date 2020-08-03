#![allow(unused)]

mod utils;

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
pub mod interface;
#[cfg(feature = "userspace")]
pub mod userspace;

pub const LICENSE: [u8; 4] = [b'G', b'P', b'L', b'\0']; //b"GPL\0"
pub const VERSION: u32 = 0xFFFFFFFE;
