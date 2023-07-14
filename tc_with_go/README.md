## Setting up your environment

1. Install Ubuntu (22.04)
2. Update the package lists
3. Install our 6.1 kernel `sudo apt install -y linux-image-6.1.0-1006-oem linux-headers-6.1.0-1006-oem linux-tools-6.1.0-1006-oem libbpf-dev`
4. Reboot !

## Build out all the bits we need!

`bpftool btf dump file /sys/kernel/btf/vmlinux format c > ../headers/vmlinux.h` - will generate the header with all the required functions in it!
`go generate` - will generate all the stub code required for our go program to speak C

`//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" bpf tc.c -- -I../header`