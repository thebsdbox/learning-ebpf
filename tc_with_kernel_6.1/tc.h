// +build ignore
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "backends.h"

#define TC_ACT_OK 0
#define ETH_P_IP 0x0800 /* Internet Protocol packet */

enum nf_nat_manip_type {
  NF_NAT_MANIP_SRC,
  NF_NAT_MANIP_DST
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __type(key, __u16);
  __type(value, struct backends);
}
svc_map SEC(".maps");

struct bpf_ct_opts {
  __s32 netns_id;
  __s32 error;
  __u8 l4proto;
  __u8 dir;
  __u8 reserved[2];
};

// Define all of these, we use __ksym as these are defined in the kernel and the linker will work it all out 
struct nf_conn * bpf_skb_ct_alloc(struct __sk_buff * skb_ctx, struct bpf_sock_tuple * bpf_tuple, __u32 tuple__sz, struct bpf_ct_opts * opts, __u32 opts__sz) __ksym;
struct nf_conn * bpf_skb_ct_lookup(struct __sk_buff * , struct bpf_sock_tuple * , __u32, struct bpf_ct_opts * , __u32) __ksym;
struct nf_conn * bpf_ct_insert_entry(struct nf_conn * nfct_i) __ksym;
int bpf_ct_set_nat_info(struct nf_conn * nfct, union nf_inet_addr * addr, int port, enum nf_nat_manip_type manip) __ksym;
void bpf_ct_set_timeout(struct nf_conn * nfct, __u32 timeout) __ksym;
int bpf_ct_set_status(const struct nf_conn * nfct, __u32 status) __ksym;
void bpf_ct_release(struct nf_conn * ) __ksym;
