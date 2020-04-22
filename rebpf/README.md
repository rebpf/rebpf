# rebpf
rebpf is a Rust library built on top of libbpf (no bcc dependency) that allows to write and load bpf program, in details this library provides:

- A raw binding of libbpf provide by [libbpf-sys](https://github.com/alexforster/libbpf-sys).
- A safe wrapper of libbpf (Work in progress).
- High level ebpf api built on top of libbpf wrapper (Work in progress).

## Source code overview
- All functions and structs that represent a safe wrapper of libbpf are located in [lib.rs](./src/lib.rs) and [helpers.rs](./src/helpers.rs) with the same names of the functions and structs in libbpf (structs names are switched from snake_case to caml_case).

- All functions and structs that represent high level ebpf api are built on top of libbpf safe wrapper. In this moment the only module that contains high level ebpf api is [maps.rs](./src/maps.rs).

## Usage
Add to your Cargo.toml:
```toml
[dependencies]
rebpf = "0.1.2"
```
To create your first ebpf program with rebpf library you can copy and rename an [empty project template](https://github.com/uccidibuti/rebpf/tree/master/examples/empty_project) and edit it changing <your_project_name>/src/kern.rs and <your_project_name>/src/user.rs files.

## Documentations
[link](https://docs.rs/rebpf/0.1.2/rebpf/).

## Requirements
- A recent [linux kernel](https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md)
- LLVM 9
- libelf
- zlib

## Roadmap and contributions
Roadmap is composed from all issues with label "roadmap". If you want contribute to this repo to avoid future conflicts you can describe what are you implementing in a new issue with label "roadmap".

## License
Licensed under The MIT License (MIT) https://mit-license.org/.
