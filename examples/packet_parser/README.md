This example refers:
[basic-map-counter](https://github.com/xdp-project/xdp-tutorial/tree/master/basic03-map-counter)
and [packet-parsing](https://github.com/xdp-project/xdp-tutorial/tree/master/packet01-parsing)

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

Output example:
```
- $sudo ./user -i eth0
Success Loading
 XDP progsec: xdp_stats1, prog name: _xdp_stats1_fun, id 188 on device: 2

Collecting stats from BPF map
- BPF map (bpf_map_type:PERCPU_ARRAY) id:161 name:xdp_stats_map key_size:4, value_size:56, max_entries:5
Action: PASS, packets: 0, pps: 0, period: 1.000135633s, packets size = 0
-------------------------------------------------
Action: PASS, packets: 2, pps: 1, period: 2.000124818s, packets size = 156
last source mac = [116, 54, 109, 246, 154, 35], last destination mac = [248, 50, 228, 192, 50, 140]
last source ipv4 = [140, 82, 113, 26], last destination ipv4 = [192, 168, 1, 93]
-------------------------------------------------
Action: PASS, packets: 7, pps: 3, period: 2.000180514s, packets size = 867
last source mac = [116, 54, 109, 246, 154, 35], last destination mac = [248, 50, 228, 192, 50, 140]
last source ipv4 = [216, 58, 198, 46], last destination ipv4 = [192, 168, 1, 93]
...
```