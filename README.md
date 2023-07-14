# learning-ebpf

This repository is a learning guide to eBPF, and will aim to cover building projects in both C and in Golang.

## Setting up your environment

There are requirements on the Linux kernel in order for various functions to work, so as a baseline i've opted for the Linux Kernel 6.1+ (this comes with a lot of helper functions that I will be using).

### So why wait for the 6.1 Kernel?

I specifically have been waiting to implememt load balancing, but with connection tracking (Which I was going to write about in detail **BUT** [](https://arthurchiao.art/blog/conntrack-design-and-implementation/#151-network-address-translation-nat) covers most of it). So prior to this it was possible to write an eBPF powered load balancer for TCP/UDP etc.. however most examples that you will see will effectively just bounce packets between a series of backend hosts regardless of what is actually occuring within the packets. In order to maintain a stable connection between source and destination when traffic is traversing a load balancer we need to monitor and maintain a connection once it is established. Prior to this kernel release your only option was to implement connection tracking yourself within your eBPF program, which I certainly was not going to do (or was capable of doing).

## Setting up your environment

1. Install Ubuntu (22.04)
2. Update the package lists `sudo apt get update`
3. Install our 6.1 kernel `sudo apt install -y linux-image-6.1.0-1006-oem linux-headers-6.1.0-1006-oem linux-tools-6.1.0-1006-oem libbpf-dev`
4. Reboot !

## Source code structure

- `./ebpf` contains all of the source code for eBPF programs
- `./ebpf/header/` contains our "generated" eBPF header for the system where you're running.
- `./userland` contains all of the user facing programs that will interact with our eBPF programs

## Generated `eBPF` header

We can "dump" all of the required bpf type format (btf)[https://www.kernel.org/doc/html/next/bpf/btf.html], most recent kernels have `/sys/kernel/btf/vmlinux` enabled in the kernel. This file contains **all** of the required function definitions within the kernel. With the following line we can dump this to a C header, which we can `#include vmlinux.h` thus allowing our programs to understand and use the various eBPF functions within the kernel.

The following line usese the `bpftool` to parse this kernel specific file and generate the ebpf headers needed for all required programs.
```
bpftool btf dump file /sys/kernel/btf/vmlinux format c > ../../headers/vmlinux.h
```