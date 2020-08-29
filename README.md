# rebpf
rebpf is a Rust library built on top of libbpf (no bcc dependency) that allows to write and load bpf program, in details this library provides:

- A raw binding of libbpf provide by [libbpf-sys](https://github.com/alexforster/libbpf-sys).
- A safe wrapper of libbpf.
- High level ebpf api built on top of libbpf wrapper.
- Parse packets in bpf programs using [pdu](https://github.com/uccidibuti/pdu), for more details see [packet_parser](./examples/packet_parser).

For more details see [rebpf](./rebpf).

## Usage
To create your first ebpf program with rebpf library you can copy and rename an [empty_project template](./examples/empty_project) and edit it changing <your_project_name>/src/kern.rs and <your_project_name>/src/user.rs files.

### write your ebpf program
Copy this content in <your_project_name>/src/kern.rs:

```rust
#![no_std]
use rebpf::{
    LICENSE,
    VERSION,
    rebpf_macro::{sec},
    libbpf::{XdpAction, XdpMd},
};

#[sec("license")]
pub static _license: [u8; 4] = LICENSE;

#[sec("version")]
pub static _version: u32 = VERSION;

#[sec("xdp_drop")]
pub fn _xdp_drop(ctx: &XdpMd) -> XdpAction {
    XdpAction::DROP
}
```
Note: this ebpf program drop every packets received.

### write your ebpf loader program
Copy this content in <your_project_name>/src/user.rs:

```rust
use rebpf::{libbpf, interface, error as rebpf_error};
use clap::{Arg, App};
use std::path::Path;

const DEFAULT_FILENAME: &str = "kern.o";
const DEFAULT_DEV: &str = "wlan0";

fn load_bpf(interface: &interface::Interface, bpf_program_path: &Path, xdp_flags: libbpf::XdpFlags) -> Result<(), rebpf_error::Error> {
    let (_bpf_object, bpf_fd) = libbpf::bpf_prog_load(bpf_program_path, libbpf::BpfProgType::XDP)?;
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

fn run(bpf_program_path: &Path, interface_name: &str, unload_program: bool) -> Result<(), rebpf_error::Error> {
    let interface = interface::get_interface(interface_name)?;
    let xdp_flags = libbpf::XdpFlags::UPDATE_IF_NOEXIST | libbpf::XdpFlags::SKB_MODE;
    if unload_program == false {
        load_bpf(&interface, bpf_program_path, xdp_flags)
    } else {
        unload_bpf(&interface, xdp_flags)
    }    
}

fn main() {
    let bpf_program_path = Path::new(DEFAULT_FILENAME);
    let unload_program = false;
    match run(&bpf_program_path, DEFAULT_DEV, unload_program) {
        Err(err) => println!("{:?}", err),
        Ok(_) => {}
    };
}

```

### compile ebpf and loader programs
Move into <your_project_name> folder and run the script build.sh:
```
cd <your_project_name>
./build.sh
```

### load and run ebpf program
```
cd <your_project_name>/ebpf_output
sudo user
```
Expected output:
```
Success Loading
 XDP prog name: _xdp_drop, id 33 on device: 2
```

### about empty_project template
[empty_project template](./examples/empty_project) allows to write bpf programs and bpf userspace loader in a single Rust project and compile both with [build.sh](./examples/empty_project/build.sh) script but it is also possible does two different project and compile both apart:
- To compile bpf userspace loader project it is possible use "cargo build --release".
- Because Rust compiler doesn't allow to emit bpf bytecode, to compile bpf project the only way is emit llvm-bytecode with Rust compiler and convert it with llc into bpf bytecode (llvm allows to compile llvm-bytecode into bpf-bytecode).

## Examples
[link](https://github.com/rebpf/rebpf/tree/master/examples).

## Documentations
[link](https://docs.rs/rebpf/latest/rebpf/).

## About writing bpf programs in Rust
To allows that bpf verifier accept your Rust bpf program you must be sure that in your source code all functions are inline and that you check all array access explicity with a if condition (you must check the array pointer address and not the slice length). Besides there are some Rust core/std functions that internally call #inline(never) functions (i.e. [SliceIndex](https://doc.rust-lang.org/src/core/slice/mod.rs.html#2747)) and there isn't away to force Rust compiler to compile these functions inline, so to fix this problem i have made a bash scripts [build.sh](./examples/empty_project/build.sh) and [remove_undefined_functions.sh](./examples/empty_project/remove_undefined_functions.sh) that automatically remove these functions from llvm-bytecode before compile to bpf-bytecode and then allow you to use Rust core functions writing bpf programs in Rust.     

## Requirements
- A recent [linux kernel](https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md)
- LLVM 9
- libelf
- zlib

## Roadmap and contributions
Roadmap is composed from all issues with label "roadmap". If you want contribute to this repo to avoid future conflicts you can describe what are you implementing in a new issue with label "roadmap".

## License
Licensed under The MIT License (MIT) https://mit-license.org/.
