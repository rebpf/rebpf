// This code is released under the
// General Public License (GPL), version 3
// http://www.gnu.org/licenses/gpl-3.0.en.html
// (c) Lorenzo Vannucci

use rebpf::{libbpf, interface, error as rebpf_error};
use clap::{Arg, App};
use std::path::Path;

const DEFAULT_FILENAME: &str = "kern.o";
const DEFAULT_PROG_SEC: &str = "xdp_pass";
const DEFAULT_DEV: &str = "wlan0";

fn load_bpf(interface: &interface::Interface, bpf_program_path: &Path, xdp_flags: libbpf::XdpFlags, program_name: &str) -> Result<(), rebpf_error::Error> {
    let (bpf_object, _bpf_fd) = libbpf::bpf_prog_load(bpf_program_path, libbpf::BpfProgType::XDP)?;
    let bpf_prog = libbpf::bpf_object__find_program_by_title(&bpf_object, program_name)?;
    let bpf_fd = libbpf::bpf_program__fd(&bpf_prog)?;
    libbpf::bpf_set_link_xdp_fd(&interface, Some(&bpf_fd), xdp_flags)?;
    let info = libbpf::bpf_obj_get_info_by_fd(&bpf_fd)?;
    println!("Success Loading\n XDP prog name: {}, id {} on device: {}", info.name()?, info.id(), interface.ifindex());
    
    Ok(())
}

fn unload_bpf(interface: &interface::Interface, xdp_flags: libbpf::XdpFlags) -> Result<(), rebpf_error::Error> {
    libbpf::bpf_set_link_xdp_fd(&interface, None, xdp_flags)?;
    println!("Success Unloading.");

    Ok(())
}

fn run(bpf_program_path: &Path, interface_name: &str, program_name: Option<&str>) -> Result<(), rebpf_error::Error> {
    let interface = interface::get_interface(interface_name)?;
    let xdp_flags = libbpf::XdpFlags::UPDATE_IF_NOEXIST | libbpf::XdpFlags::SKB_MODE;
    if let Some(program_name) = program_name {
        load_bpf(&interface, bpf_program_path, xdp_flags, program_name)
    } else {
        unload_bpf(&interface, xdp_flags)
    }    
}

fn main() -> Result<(), rebpf_error::Error> {
    let matches = App::new("prog_by_name")
        .version("1.0")
        .author("Lorenzo Vannucci lorenzo@vannucci.io")
        .arg(Arg::with_name("i")
             .short("i")
             .long("interface")
             .value_name("interface")
             .help("Sets interface to attach xdp program")
             .takes_value(true)
        ).arg(Arg::with_name("p")
              .short("p")
              .long("program")
              .value_name("program")
              .help("Name of the program to load")
              .takes_value(true)
        ).arg(Arg::with_name("U")
              .short("U")
              .long("unload")
              .value_name("unload")
              .help("Unload XDP program instead of loading")
              .takes_value(false)
        ).get_matches();

    let interface_name = matches.value_of("i").unwrap_or(DEFAULT_DEV);
    let program_name = if !matches.is_present("U") {
        Some(matches.value_of("p").unwrap_or(DEFAULT_PROG_SEC))
    } else {
        None
    };
    println!("{:?}", program_name);
    let bpf_program_path = Path::new(DEFAULT_FILENAME);
    run(&bpf_program_path, interface_name, program_name)
}
