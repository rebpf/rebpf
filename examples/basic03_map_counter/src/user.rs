// This code is released under the
// General Public License (GPL), version 3
// http://www.gnu.org/licenses/gpl-3.0.en.html
// (c) Lorenzo Vannucci

use clap::{App, Arg};
use rebpf::{self, error as rebpf_error, interface, xdp};
use std::path::Path;
use std::sync::atomic::Ordering::Relaxed;

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
    xdp_flags: &[xdp::XdpFlags],
) -> Result<rebpf::BpfObject, rebpf_error::Error> {
    let (bpf_object, _bpf_fd) = rebpf::bpf_prog_load(bpf_program_path, rebpf::BpfProgType::XDP)?;
    let bpf_prog = rebpf::bpf_object__find_program_by_title(&bpf_object, prog_sec)?
        .ok_or(rebpf_error::Error::InvalidProgSec)?;
    let bpf_fd = rebpf::bpf_program__fd(&bpf_prog)?;
    xdp::bpf_set_link_xdp_fd(&interface, Some(&bpf_fd), &xdp_flags)?;
    let info = rebpf::bpf_obj_get_info_by_fd(&bpf_fd)?;
    println!(
        "Success Loading\n XDP progsec: {}, prog name: {}, id {} on device: {}",
        prog_sec,
        info.name()?,
        info.id(),
        interface.ifindex()
    );

    Ok(bpf_object)
}

fn find_map_by_fd<T, U>(
    bpf_object: &rebpf::BpfObject,
    map_name: &str,
) -> Result<rebpf::BpfMapFd<T, U>, rebpf_error::Error> {
    let bpf_map = rebpf::bpf_object__find_map_by_name(bpf_object, map_name)?
        .ok_or(rebpf_error::Error::InvalidMapName)?;

    rebpf::bpf_map__fd(&bpf_map)
}

fn check_map_fd_info<T, U>(
    bpf_map_fd: &rebpf::BpfMapFd<T, U>,
    map_expected: &rebpf::BpfMapInfo,
) -> Result<rebpf::BpfMapInfo, rebpf_error::Error> {
    let map_info = rebpf::bpf_obj_get_info_by_fd(bpf_map_fd)?;
    if map_expected.type_() as u32 != map_info.type_() as u32 {
        return Err(rebpf_error::Error::CustomError(
            "Error occured in map key size.".to_string(),
        ));
    }
    if map_expected.key_size() != map_info.key_size() {
        return Err(rebpf_error::Error::CustomError(
            "Error occured in map key size.".to_string(),
        ));
    }
    if map_expected.max_entries() != map_info.max_entries() {
        return Err(rebpf_error::Error::CustomError(
            "Error occured in map max entries.".to_string(),
        ));
    }
    if map_expected.value_size() != map_info.value_size() {
        return Err(rebpf_error::Error::CustomError(
            "Error occured in map value size.".to_string(),
        ));
    }

    Ok(map_info)
}

fn unload_bpf(
    interface: &interface::Interface,
    xdp_flags: &[xdp::XdpFlags],
) -> Result<(), rebpf_error::Error> {
    xdp::bpf_set_link_xdp_fd(&interface, None, &xdp_flags)?;
    println!("Success Unloading.");

    Ok(())
}

struct Record {
    timestamp: std::time::Instant,
    total: DataRec,
}

impl Record {
    fn new() -> Record {
        Record {
            timestamp: std::time::Instant::now(),
            total: DataRec {
                rx_packets: std::sync::atomic::AtomicU64::new(0),
            },
        }
    }
}

struct StatsRecord {
    stats: [Record; 1],
}

impl StatsRecord {
    fn new() -> StatsRecord {
        StatsRecord {
            stats: [Record::new()],
        }
    }
}

fn map_collect(
    bpf_map_fd: &rebpf::BpfMapFd<u32, DataRec>,
    map_type: &rebpf::BpfMapType,
    key: u32,
    rec: &mut Record,
) {
    let mut value: DataRec = unsafe { std::mem::zeroed() };
    rec.timestamp = std::time::Instant::now();

    match map_type {
        rebpf::BpfMapType::ARRAY => {
            if rebpf::bpf_map_lookup_elem(bpf_map_fd, &key, &mut value).is_some() {
                rec.total.rx_packets = value.rx_packets;
            }
        }
        _ => {}
    }
}

fn stats_poll(
    bpf_map_fd: &rebpf::BpfMapFd<u32, DataRec>,
    map_type: &rebpf::BpfMapType,
    interval: u64,
) {
    let mut record = StatsRecord::new();

    let key = xdp::XdpAction::PASS as u32;
    map_collect(bpf_map_fd, map_type, key, &mut record.stats[0]);
    std::thread::sleep(std::time::Duration::from_secs(1));
    loop {
        let prev = unsafe { std::mem::transmute_copy(&mut record) };
        map_collect(bpf_map_fd, map_type, key, &mut record.stats[0]);
        stats_print(&record, &prev);
        std::thread::sleep(std::time::Duration::from_secs(interval));
    }
}

fn stats_print(stats_rec: &StatsRecord, stats_prev: &StatsRecord) {
    let rec = &stats_rec.stats[0];
    let prev = &stats_prev.stats[0];

    let time = rec.timestamp.duration_since(prev.timestamp);
    let packets = (rec.total.rx_packets.load(Relaxed) - prev.total.rx_packets.load(Relaxed)) as u64;
    let pps = packets / time.as_secs();
    println!(
        "Action: {:?}, packets: {}, pps: {}, period: {:?}",
        xdp::XdpAction::PASS,
        packets,
        pps,
        time
    )
}

fn run(
    bpf_program_path: &Path,
    interface_name: &str,
    prog_sec: &str,
    map_name: &str,
    unload_program: bool,
) -> Result<(), rebpf_error::Error> {
    let interface = interface::get_interface(interface_name)?;
    let xdp_flags = vec![xdp::XdpFlags::UPDATE_IF_NOEXIST, xdp::XdpFlags::SKB_MODE];
    if unload_program == true {
        return unload_bpf(&interface, &xdp_flags);
    }
    let bpf_object = load_bpf(&interface, bpf_program_path, prog_sec, &xdp_flags)?;
    let stats_map_fd = find_map_by_fd::<u32, DataRec>(&bpf_object, map_name)?;
    let map_expect = rebpf::BpfMapDef::<u32, DataRec>::new(rebpf::BpfMapType::ARRAY, MAX_ENTRIES)
        .to_bpf_map_info();
    let map_info = check_map_fd_info(&stats_map_fd, &map_expect)?;
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

    stats_poll(&stats_map_fd, &map_info.type_(), 2);

    Ok(())
}

fn main() {
    let matches = App::new("map_counter")
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
    match run(
        &bpf_program_path,
        interface_name,
        DEFAULT_PROG_SEC,
        DEFAULT_MAPNAME,
        unload_program,
    ) {
        Err(err) => println!("{:?}", err),
        Ok(_) => {}
    };
}
