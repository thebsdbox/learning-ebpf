// +build ignore

#include "../headers/vmlinux.h"
#include "tc.h"

// Called by the tc_ingress function (which is attached to the ingress of a network interface)
int balance(struct __sk_buff * ctx) {

// Parse the data (which should be an ethernet frame)
  void * data_end = (void * )(long) ctx -> data_end;
  void * data = (void * )(long) ctx -> data;
  struct ethhdr * eth = data;

  __u64 nh_off = sizeof( * eth);

  if (data + nh_off > data_end)
    return TC_ACT_OK;
// If it's an ethernet frame determine if it's IP and TCP/UDP
  if (bpf_ntohs(eth -> h_proto) == ETH_P_IP) {

    struct bpf_sock_tuple bpf_tuple = {};
    struct iphdr * iph = data + nh_off;
    struct bpf_ct_opts opts_def = {
      .netns_id = -1,
    };
    struct nf_conn * conntrack;

    if ((void * )(iph + 1) > data_end)
      return TC_ACT_OK;

    opts_def.l4proto = iph -> protocol;
    bpf_tuple.ipv4.saddr = iph -> saddr;
    bpf_tuple.ipv4.daddr = iph -> daddr;

    if (iph -> protocol == IPPROTO_TCP) {
      struct tcphdr * tcph = (struct tcphdr * )(iph + 1);

      if ((void * )(tcph + 1) > data_end)
        return TC_ACT_OK;

      bpf_tuple.ipv4.sport = tcph -> source;
      bpf_tuple.ipv4.dport = tcph -> dest;
    } else if (iph -> protocol == IPPROTO_UDP) {
      struct udphdr * udph = (struct udphdr * )(iph + 1);

      if ((void * )(udph + 1) > data_end)
        return TC_ACT_OK;

      bpf_tuple.ipv4.sport = udph -> source;
      bpf_tuple.ipv4.dport = udph -> dest;
    } else {
      // Neither TCP or UDP, so ignore the packet
      return TC_ACT_OK;
    }
  
    // Store the destination port to use as a lookup key
    __u16 key = bpf_ntohs(bpf_tuple.ipv4.dport);
    struct backends * lookup;
    lookup = (struct backends * ) bpf_map_lookup_elem( & svc_map, & key);

    if (lookup) {
      bpf_printk("found backends for the incoming port %d %pI4 / %pI4", key, &lookup -> backend1, &lookup -> backend2);
    } else {
      // No backends, pass the packet onwards
      return TC_ACT_OK;
    }
    // Look for existing contrack
    conntrack = bpf_skb_ct_lookup(ctx, & bpf_tuple, sizeof(bpf_tuple.ipv4), & opts_def, sizeof(opts_def));
    if (conntrack) {
      bpf_printk("found existing conntrack ID: 0x%X", conntrack);
      bpf_printk("timeout %u status %X dport %X",conntrack -> timeout, conntrack -> status, bpf_htons(bpf_tuple.ipv4.dport));
      // decrement reference count on a conntrack
      bpf_ct_release(conntrack);
    } else {
      // Create a new conntrack entry
      struct nf_conn * newConntrack = bpf_skb_ct_alloc(ctx, & bpf_tuple, sizeof(bpf_tuple.ipv4), & opts_def, sizeof(opts_def));

      if (!newConntrack) {
        bpf_printk("failed to allocate a new conntrack entry");
        return TC_ACT_OK;
      }

      bpf_printk("incoming %pI4:%d, protocol: %u",&(iph -> daddr),bpf_tuple.ipv4.dport, iph -> protocol);

      union nf_inet_addr addr = {};
      //default to first backend
      addr.ip = lookup -> backend1;
      // Rudimentary load balancing for now based on received source port
      if (bpf_htons(bpf_tuple.ipv4.sport) % 2) {
        addr.ip = lookup -> backend2;
      }
      bpf_printk("backend %pI4:%d",&(addr.ip),lookup -> destPort);

      // DNAT is set to the backend
      bpf_ct_set_nat_info(newConntrack, & addr, lookup -> destPort, NF_NAT_MANIP_DST);

      // SNAT is set to the host
      addr.ip = bpf_tuple.ipv4.daddr;
      bpf_ct_set_nat_info(newConntrack, & addr, -1, NF_NAT_MANIP_SRC);
      bpf_ct_set_timeout(newConntrack, 30000);
      // Set this as a new connection to be tracked
      bpf_ct_set_status(newConntrack, IP_CT_NEW);

      conntrack = bpf_ct_insert_entry(newConntrack);

      bpf_printk("bpf_ct_insert_entry() returned ct 0x%x", conntrack);

      if (conntrack) {
        // decrement reference count on a conntrack
        bpf_ct_release(conntrack);
      }
    }
  }
  return TC_ACT_OK;
}

SEC("tc")
int tc_ingress(struct __sk_buff * ctx) {
  return balance(ctx);
}

char __license[] SEC("license") = "GPL";