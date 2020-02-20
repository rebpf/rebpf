use rebpf::{xdp::XdpAction, LICENSE, VERSION, rebpf_macro::sec};

#[sec("xdp")]
fn xdp_prog_simple() -> XdpAction {
    XdpAction::PASS
}

#[sec("license")]
pub static _license: [u8; 4] = LICENSE;

#[sec("version")]
pub static _version: u32 = VERSION;
