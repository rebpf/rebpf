#[allow(unused_imports)]
use rebpf::{LICENSE, VERSION, rebpf_macro::sec};

#[sec("license")]
pub static _license: [u8; 4] = LICENSE;

#[sec("version")]
pub static _version: u32 = VERSION;

#[sec("my_function")]
fn _my_function() {
}
