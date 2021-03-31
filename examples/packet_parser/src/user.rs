// This code is released under the
// General Public License (GPL), version 3
// http://www.gnu.org/licenses/gpl-3.0.en.html
// (c) Lorenzo Vannucci

use clap::{App, Arg};
//use rebpf::maps::Lookup;
//use rebpf::userspace::maps::Array;
use rebpf::userspace::maps::{PerCpuArray, Lookup};
use rebpf::{error as rebpf_error, interface, libbpf};
use std::path::Path;
//use std::sync::atomic::Ordering::Relaxed;

mod common_kern_user;
use common_kern_user::{DataRec, MAX_ENTRIES};

const DEFAULT_FILENAME: &str = "kern.o";
const DEFAULT_PROG_SEC: &str = "xdp_stats1";
const DEFAULT_DEV: &str = "wlan0";
const DEFAULT_MAPNAME: &str = "xdp_stats_map";

fn load_bpf(
    interface: &interface::Interface,
    bpf_program_path: &Path,
    prog_sec: &str,
    xdp_flags: libbpf::XdpFlags,
) -> Result<libbpf::BpfObject, rebpf_error::Error> {
    let (bpf_object, _bpf_fd) = libbpf::bpf_prog_load(bpf_program_path, libbpf::BpfProgType::XDP)?;
    let bpf_prog = libbpf::bpf_object__find_program_by_title(&bpf_object, prog_sec)?;
    let bpf_fd = libbpf::bpf_program__fd(&bpf_prog)?;
    libbpf::bpf_set_link_xdp_fd(&interface, Some(&bpf_fd), xdp_flags)?;
    let info = libbpf::bpf_obj_get_info_by_fd(&bpf_fd)?;
    println!(
        "Success Loading\n XDP progsec: {}, prog name: {}, id {} on device: {}",
        prog_sec,
        info.name()?,
        info.id(),
        interface.ifindex()
    );

    Ok(bpf_object)
}

fn unload_bpf(
    interface: &interface::Interface,
    xdp_flags: libbpf::XdpFlags,
) -> Result<(), rebpf_error::Error> {
    libbpf::bpf_set_link_xdp_fd(&interface, None, xdp_flags)?;
    println!("Success Unloading.");

    Ok(())
}

struct Record {
    timestamp: std::time::Instant,
    total: DataRec,
}

fn map_collect(bpf_map: &PerCpuArray<DataRec>, key: u32) -> Record {
    Record {
        total: match bpf_map.lookup(&key) {
            Some(values) => {
                let mut packets_size = 0;
                let mut count_cpu_rx_packets = 0;
                let mut rx_packets = 0;
                let mut source_mac = [0u8; 6];
                let mut source_ipv4 = [0u8; 4];
                let mut dest_ipv4 = [0u8; 4];
                let mut dest_mac = [0u8; 6];
                for v in values.as_ref() {
                    let v: DataRec = *v.as_ref();
                    rx_packets += v.rx_packets;
                    if v.rx_packets > 0 {
                        count_cpu_rx_packets += 1;
                        packets_size += v.packets_size;
                        source_mac = v.last_source_mac;
                        dest_mac = v.last_dest_mac;
                        source_ipv4 = v.last_source_ipv4;
                        dest_ipv4 = v.last_dest_ipv4;
                    }
                }
                let mut v: DataRec = values.first().unwrap().as_ref().clone();
                v.rx_packets = rx_packets;
                if count_cpu_rx_packets > 0 {
                    v.packets_size = packets_size;
                    v.last_source_mac = source_mac;
                    v.last_dest_mac = dest_mac;
                    v.last_source_ipv4 = source_ipv4;
                    v.last_dest_ipv4 = dest_ipv4;
                }
                v
            }
            _ => panic!("Element not found in map"),
        },
        timestamp: std::time::Instant::now(),
    }
}

fn stats_print(rec: &Record, prev: &Record) {
    let time = rec.timestamp.duration_since(prev.timestamp);
    let packets = (rec.total.rx_packets - prev.total.rx_packets) as u64;
    let packets_size = (rec.total.packets_size - prev.total.packets_size) as u64;
    let pps = packets / time.as_secs();
    println!(
        "Action: {:?}, packets: {}, pps: {}, period: {:?}, packets size = {}",
        libbpf::XdpAction::PASS,
        packets,
        pps,
        time,
        packets_size,
    );

    if packets > 0 {
        println!(
            "last source mac = {:?}, last destination mac = {:?}",
            rec.total.last_source_mac, rec.total.last_dest_mac,
        );
        println!(
            "last source ipv4 = {:?}, last destination ipv4 = {:?}",
            rec.total.last_source_ipv4, rec.total.last_dest_ipv4,
        );
    }
    println!("-------------------------------------------------");
}

fn stats_poll(bpf_map: &PerCpuArray<DataRec>, interval: u64) {
    let key = libbpf::XdpAction::PASS as u32;
    let mut previous = map_collect(bpf_map, key);
    std::thread::sleep(std::time::Duration::from_secs(1));
    loop {
        let mut current = map_collect(bpf_map, key);
        stats_print(&current, &previous);
        std::mem::swap(&mut current, &mut previous);
        std::thread::sleep(std::time::Duration::from_secs(interval));
    }
}

fn run(
    bpf_program_path: &Path,
    interface_name: &str,
    prog_sec: &str,
    map_name: &str,
    unload_program: bool,
) -> Result<(), rebpf_error::Error> {
    let interface = interface::get_interface(interface_name)?;
    let xdp_flags = libbpf::XdpFlags::UPDATE_IF_NOEXIST | libbpf::XdpFlags::SKB_MODE;
    if unload_program == true {
        return unload_bpf(&interface, xdp_flags);
    }
    let bpf_object = load_bpf(&interface, bpf_program_path, prog_sec, xdp_flags)?;
    let stats_map = PerCpuArray::<DataRec>::from_obj(&bpf_object, map_name)?;
    let map_info = stats_map.extract_info()?;
    assert!(map_info.max_entries() == MAX_ENTRIES);
    println!("\nCollecting stats from BPF map");
    println!(
        "- BPF map (bpf_map_type:{:?}) id:{} name:{} key_size:{}, value_size:{}, max_entries:{}",
        map_info.type_(),
        map_info.id(),
        map_info.name()?,
        map_info.key_size(),
        map_info.value_size(),
        map_info.max_entries()
    );

    stats_poll(&stats_map, 2);

    Ok(())
}

fn main() -> Result<(), rebpf_error::Error> {
    let matches = App::new("packet_parser")
        .version("1.0")
        .author("Lorenzo Vannucci lorenzo@vannucci.io")
        .arg(
            Arg::with_name("i")
                .short("i")
                .long("interface")
                .value_name("interface")
                .help("Sets interface to attach xdp program")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("U")
                .short("U")
                .long("unload")
                .value_name("unload")
                .help("Unload XDP program instead of loading")
                .takes_value(false),
        )
        .get_matches();

    let interface_name = matches.value_of("i").unwrap_or(DEFAULT_DEV);
    let unload_program = matches.is_present("U");
    let bpf_program_path = Path::new(DEFAULT_FILENAME);
    run(
        &bpf_program_path,
        interface_name,
        DEFAULT_PROG_SEC,
        DEFAULT_MAPNAME,
        unload_program,
    )
}
