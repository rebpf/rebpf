This project represent an example of a new empty project that use rebpf library. To create a new bpf project that use rebpf library you can use this project as template changing the name of the project in Cargo.toml. For more details on how create and load an ebpf program you can see others rebpf examples.

### How this project is structured:

- src/kern.rs: that will be compiled to bpf progam (ebpf_output/kern.bc, ebpf_output/kern.o).
- src/user.rs: that will be compiled to a user program load to load ebf program (ebpf_output/user).
- build.sh: script that compile src/kern.rs into ebpf_output/kern.bc, ebpf_output/kern.o and src/user.rs into ebpf_output/user.
