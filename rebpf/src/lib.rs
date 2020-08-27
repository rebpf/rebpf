//! # rebpf
//! rebpf is a Rust library built on top of libbpf (no bcc dependency)
//! that allows to write and load bpf program, in details this library provides:
//!    - A raw binding of libbpf provide by [`libbpf-sys`].
//!    - A safe wrapper of libbpf.
//!    - High level ebpf api built on top of libbpf wrapper to load and write bpf programs.
//!    - Parse packets in bpf programs using [`pdu`], for more details see [`packet_parser`].
//!
//! [`libbpf-sys`]: https://github.com/alexforster/libbpf-sys
//! [`pdu`]: https://github.com/uccidibuti/pdu
//! [`packet_parser`]: https://github.com/rebpf/rebpf/tree/master/examples/packet_parser

#![allow(unused)]

mod utils;

#[macro_use]
extern crate function_name;

pub use rebpf_macro;

pub mod error;
pub mod libbpf;
mod maps;

#[cfg(feature = "bpf")]
pub mod bpf;
#[cfg(feature = "bpf")]
pub mod helpers;

#[cfg(feature = "userspace")]
pub mod interface;
#[cfg(feature = "userspace")]
pub mod map_layout;
#[cfg(feature = "userspace")]
pub mod userspace;

pub const LICENSE: [u8; 4] = [b'G', b'P', b'L', b'\0']; //b"GPL\0"
pub const VERSION: u32 = 0xFFFFFFFE;
