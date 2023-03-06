# TC - Traffic Control with the Linux Kernel 6.1+ (using Ubuntu 2204)

This repository contains all the code for building your own eBPF load balancer using the new helper functions that are available within the 6.1+ Kernel.

## So why wait for the 6.1 Kernel?

I specifically have been waiting to implememt load balancing, but with connection tracking (Which I was going to write about in detail **BUT** [](https://arthurchiao.art/blog/conntrack-design-and-implementation/#151-network-address-translation-nat) covers most of it). So prior to this it was possible to write an eBPF powered load balancer for TCP/UDP etc.. however most examples that you will see will effectively just bounce packets between a series of backend hosts regardless of what is actually occuring within the packets. In order to maintain a stable connection between source and destination when traffic is traversing a load balancer we need to monitor and maintain a connection once it is established. Prior to this kernel release your only option was to implement connection tracking yourself within your eBPF program, which I certainly was not going to do (or was capable of doing).

## The new eBPF helpers!

Everyone loves a helper, and eBPF is no different! As work continues on within the eBPF ecosystem a lot of regular kernel functions are being exposed within your eBPF program through these helpers. With recent kernel versions the conntrack functions are now exposed to your eBPF programs, along with the capability to perform SNAT and DNAT! Some details are here [](https://lwn.net/Articles/902023/).

### The new functions in question

`struct nf_conn * bpf_skb_ct_alloc(struct __sk_buff * skb_ctx, struct bpf_sock_tuple * bpf_tuple, __u32 tuple__sz, struct bpf_ct_opts * opts, __u32 opts__sz) __ksym;`
This function will allocate a new conntrack struct

`struct nf_conn * bpf_skb_ct_lookup(struct __sk_buff * , struct bpf_sock_tuple * , __u32, struct bpf_ct_opts * , __u32) __ksym;`
This function will lookup a connection tracking by looking up a tuple and returning the tracking (if it exists)

`struct nf_conn * bpf_ct_insert_entry(struct nf_conn * nfct_i) __ksym;`
This will add our new conntrack entry into the system.

`int bpf_ct_set_nat_info(struct nf_conn * nfct, union nf_inet_addr * addr, int port, enum nf_nat_manip_type manip) __ksym;`
Specify the NAT settings for this conntrack entry with a new address for a specific port using either `NF_NAT_MANIP_DST`(DNAT) or `NF_NAT_MANIP_SRC`(SNAT).

`void bpf_ct_set_timeout(struct nf_conn * nfct, __u32 timeout) __ksym;`
Specify the timeout (length before expiry) of a conntrack entry

`int bpf_ct_set_status(const struct nf_conn * nfct, __u32 status) __ksym;`
Set the status of a conntrack entry such as `IP_NEW` if it is a new entry

`void bpf_ct_release(struct nf_conn * ) __ksym;`
Release a reference count on a conntrack entry (for tidying up entries).

## The code

`tc.c` contains our eBPF code
`tc.h` contains all of our function and type definitions for our eBPF code
`backends.h` shared between eBPF and our userland code
`ux.` contains our userland code used to add entries to eBPF maps

The code is heavily commented to help new users (hopefully) understand some of what is happening, but effectively it will intercept all incoming traffic on an interface on a specific port and loadbalance it to two backends/port. 

## Setting up your environment

1. Install Ubuntu (22.04)
2. Update the package lists
3. Install our 6.1 kernel `sudo apt install -y linux-image-6.1.0-1006-oem linux-headers-6.1.0-1006-oem linux-tools-6.1.0-1006-oem libbpf-dev`
4. Reboot !

## Building the code

The `/make.sh` will build our skeleton code using `bpftool` and merge it all together into a single binary that will inject the eBPF code at runtime.

## Thanks

Goes out to a number of repos with example code, the kernel test(s) and a few other places.
