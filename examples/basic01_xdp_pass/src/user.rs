// This code is released under the
// General Public License (GPL), version 3
// http://www.gnu.org/licenses/gpl-3.0.en.html
// (c) Lorenzo Vannucci

use rebpf::{self, interface,  error as rebpf_error};
use clap::{Arg, App};
use std::path::Path;

const DEFAULT_FILENAME: &str = "kern.o";
const DEFAULT_DEV: &str = "wlan0";

fn load_bpf(interface: &interface::Interface, bpf_program_path: &Path, xdp_flags: rebpf::XdpFlags) -> Result<(), rebpf_error::Error> {
    let (_bpf_object, bpf_fd) = rebpf::bpf_prog_load(bpf_program_path, rebpf::BpfProgType::XDP)?;
    rebpf::bpf_set_link_xdp_fd(&interface, Some(&bpf_fd), xdp_flags)?;
    let info = rebpf::bpf_obj_get_info_by_fd(&bpf_fd)?;
    println!("Success Loading\n XDP prog name: {}, id {} on device: {}", info.name()?, info.id(), interface.ifindex());
    
    Ok(())
}

fn unload_bpf(interface: &interface::Interface, xdp_flags: rebpf::XdpFlags) -> Result<(), rebpf_error::Error> {
    rebpf::bpf_set_link_xdp_fd(&interface, None, xdp_flags)?;
    println!("Success Unloading.");

    Ok(())
}

fn run(bpf_program_path: &Path, interface_name: &str, unload_program: bool) -> Result<(), rebpf_error::Error> {
    let interface = interface::get_interface(interface_name)?;
    let xdp_flags = rebpf::XdpFlags::UPDATE_IF_NOEXIST | rebpf::XdpFlags::SKB_MODE;
    if unload_program == false {
        load_bpf(&interface, bpf_program_path, xdp_flags)
    } else {
        unload_bpf(&interface, xdp_flags)
    }    
}


fn main() {
    let matches = App::new("xdp_pass")
        .version("1.0")
        .author("Lorenzo Vannucci lorenzo@vannucci.io")
        .arg(Arg::with_name("i")
             .short("i")
             .long("interface")
             .value_name("interface")
             .help("Sets interface to attach xdp program")
             .takes_value(true)
        ).arg(Arg::with_name("U")
              .short("U")
              .long("unload")
              .value_name("unload")
              .help("Unload XDP program instead of loading")
             .takes_value(false)
        ).get_matches();

    let interface_name = matches.value_of("i").unwrap_or(DEFAULT_DEV);
    let unload_program = matches.is_present("U");
    let bpf_program_path = Path::new(DEFAULT_FILENAME);
    match run(&bpf_program_path, interface_name, unload_program) {
        Err(err) => println!("{:?}", err),
        Ok(_) => {}
    };
}
