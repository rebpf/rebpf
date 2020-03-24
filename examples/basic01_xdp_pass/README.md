This example refers:
[basic-prog-by-name](https://github.com/xdp-project/xdp-tutorial/tree/master/basic01-xdp-pass)

To compile:
```
- ./build.sh
```

To load / unload bpf kern program, note: replace eth0 with yours interface name (without -i parameters on default is wlan0):
```
- cd ebpf_output
- sudo ./user -i eth0 // to load kern.o bpf program
- sudo ./user -i eth0 -U // to unload kern.o bpf program
```