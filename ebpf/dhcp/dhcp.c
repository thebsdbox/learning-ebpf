// +build ignore

#include "../headers/vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <string.h>

#pragma pack(1)
#include "dhcp.h"

char __license[] SEC("license") = "GPL";

#define TC_ACT_OK 0
#define ETH_P_IP 0x0800 /* Internet Protocol packet */
#define ETH_HLEN 14     /*Ethernet Header Length */

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __type(key, __u8[6]);
  __type(value, dhcp_entry);
} mac_lookup SEC(".maps");
// This map stores the MAC address as the key and the Address and DHCP state as
// the value

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __type(key, __u32);  // address
  __type(value, __u8); // DHCP message state
} dhcp_state SEC(".maps");

static inline int read_dhcp(struct __sk_buff *skb, int isIngress) {
  void *data_end = (void *)(long)skb->data_end;
  void *data = (void *)(long)skb->data;
  struct ethhdr *eth = data;
  __u16 h_proto;
  __u64 nh_off = 0;
  nh_off = sizeof(*eth);

  if (data + nh_off > data_end) {
    return TC_ACT_OK;
  }

  h_proto = eth->h_proto;
  char mac[6];
  for (int i = 0; i < 6; i++) {
    mac[i] = eth->h_source[i];
  }

  dhcp_entry *state = bpf_map_lookup_elem(&mac_lookup, mac);
  if (state) {
    bpf_printk("[MAP] Found %pI4 in eBPF map for MAC address starting %:%x:%x",
               &state->address, mac[0], mac[1], mac[2]);
  } else {
    bpf_printk("[MAP] wrong MAC address starting %x:%x:%x", mac[0], mac[1],
               mac[2]);

    return TC_ACT_OK;
  }

  if (h_proto == bpf_htons(ETH_P_IP)) {
    struct iphdr *iph = data + nh_off;

    if ((void *)(iph + 1) > data_end) {
      return 0;
    }

    if (iph->protocol != IPPROTO_UDP) {
      return 0;
    }
    __u32 ip_hlen = 0;
    //__u32 poffset = 0;
    //__u32 plength = 0;
    // __u32 ip_total_length = bpf_ntohs(iph->tot_len);

    ip_hlen = iph->ihl << 2;

    if (ip_hlen < sizeof(*iph)) {
      return 0;
    }
    struct udphdr *udph = data + nh_off + sizeof(*iph);

    if ((void *)(udph + 1) > data_end) {
      return 0;
    }
    __u16 src_port = bpf_ntohs(udph->source);
    __u16 dst_port = bpf_ntohs(udph->dest);

    if (src_port == 67 || dst_port == 67) {

      // Get the DNS Header
      struct dhcp_message *dhcp_m =
          data + sizeof(*eth) + sizeof(*iph) + sizeof(*udph);
      if ((void *)(dhcp_m + 1) > data_end) {
        return 0;
      }

      // dhcp_entry *entry;
      __u8 op = dhcp_m->dp_op;
      switch (op) {
      case DHCP_BOOTREQUEST:
        bpf_printk("[DHCP] Requesting a Lease");
        // Set ethernet source as destination
        for (int i = 0; i < 6; i++) {
          eth->h_dest[i] = eth->h_source[i];
        }
        // Set ethernet source to the server MAC (TODO specified in qemu.sh)
        // __u8 mac[6] = {0x52, 0x52, 0x12, 0x11, 0x3c, 0xc0};

        // mac[0] = 0x52;
        // mac[1] = 0x52;
        // mac[2] = 0x12;
        // mac[3] = 0x11;
        // mac[4] = 0x3c;
        // mac[5] = 0xc0;

        __u8 *res = memcpy(eth->h_source, mac, sizeof(mac));

        if (!res) {
          bpf_printk("Error copying mac address");
        }
        // eth->h_source[0] = 0x52;
        // eth->h_source[1] = 0x52;
        // eth->h_source[2] = 0x12;
        // eth->h_source[3] = 0x11;
        // eth->h_source[4] = 0x3c;
        // eth->h_source[5] = 0xc0;

        iph->saddr = bpf_htonl(0xB6A86401);
        iph->daddr = state->address;

        // Switch ports
        udph->source = bpf_htons(0x43);
        udph->dest = bpf_htons(0x44);

        // Set DHCP OP to Offer
        op = dhcp_m->dp_op = 0x02;

        // Set your IP
        __u32 address = 0;
        address = dhcp_m->dp_yiaddr = state->address;
        // dhcp_entry new_entry;
        // new_entry.dhcp_state = op;
        // new_entry.address = address;

        // int update1 =
        //     bpf_map_update_elem(&mac_lookup, &mac, &new_entry, BPF_ANY);
        // if (update1 != 0) {
        //   bpf_printk("-> couldnt update map");
        // }

        // dhcp_m->dp_yiaddr = bpf_htonl(0xB6A86402);
        // dhcp_m->dp_siaddr = bpf_htonl(0xB6A86401);
        // dhcp_m->dp_giaddr = bpf_htonl(0xB6A86401);
        // if (isIngress == 1) {
        //   bpf_clone_redirect(skb, skb->ifindex, BPF_F_INGRESS);
        // }
        // bpf_clone_redirect(skb, skb->ifindex, 0);

        //__u8 state = dhcp_m->dp_op;
        // if (dhcp_m && dhcp_m->dp_op != 0) {
        //   state = dhcp_m->dp_op;
        // }
        bpf_printk("Updating map with %pI4", &address);

        int update = bpf_map_update_elem(&dhcp_state, &address, &op, BPF_ANY);
        if (update != 0) {
          bpf_printk("-> couldnt update map");
        }

        // return 7;
        // break;

        // case DHCP_BOOTREPLY:
        bpf_printk("[DHCP] Replying with Lease");

        // so weird
        bpf_printk("[DHCP] Reading from magic %d", bpf_htonl(dhcp_m->magic));
        __u8 *state;
        if (dhcp_m->dp_yiaddr != 0) {
          __u32 address = dhcp_m->dp_yiaddr;
          bpf_printk("Looking up with %pI4", &address);
          state = bpf_map_lookup_elem(&dhcp_state, &address);
          if (state) {
            bpf_printk("-> %d", *state);
          }

          if (eth) {
            char mac[6];
            for (int i = 0; i < 6; i++) {
              mac[i] = eth->h_source[i];
            }
            dhcp_entry *existing_entry;
            existing_entry = bpf_map_lookup_elem(&mac_lookup, mac);
            if (existing_entry) {
              // bpf_printk("Entry for %s -> %d", address,
              // existing_entry->address);
            }
          }
          // address = dhcp_m->dp_yiaddr;
        }

        // lets hack the options
        dhcp_offer offer = {
            .option_message_type = 53,
            .option_message_type_len = 1,
            //.option_dhcp_id_value =
            .option_subnet_mask = 1,
            .option_subnet_mask_len = 4,
            .option_subnet_mask_value = bpf_htonl(0xffffff00), // 255.255.255.0

            .option_router = 3,
            .option_router_len = 4,
            .option_router_value = bpf_htonl(0xB6A86401),

            .option_renew_time = 58,
            .option_renew_time_len = 4,
            .option_renew_time_value = bpf_htonl(0x00000708),

            .option_rebind_time = 59,
            .option_rebind_time_len = 4,
            .option_rebind_time_value = bpf_htonl(0x00000708),

            .option_lease_time = 51,
            .option_lease_time_len = 4,
            .option_lease_time_value = bpf_htonl(0x00000708),

            .option_dhcp_id = 54,
            .option_dhcp_id_len = 4,
            .option_dhcp_id_value = bpf_htonl(0xB6A86401),

            .end = 0xff,
        };

        //

        __u8 option = 0;
        __u8 option_value = 0;
        __u8 ret = bpf_skb_load_bytes(skb, 282, &option, sizeof(option));
        if (ret != 0) {
          bpf_printk("error %d", ret);
          return 0;
        }

        if (option == 53) { // This is the DHCP message type value
          ret = bpf_skb_load_bytes(skb, 282 + sizeof(option) + sizeof(__u8),
                                   &option_value, sizeof(option_value));
          if (ret != 0) {
            bpf_printk("error %d", ret);
            return 0;
          }
          // If an offer has already gone out, then send an ACK
          if (dhcp_m->dp_op == 2) {
            if (option_value == 1) {
              offer.option_message_value = 2;
            }
            if (option_value == 3) {
              offer.option_message_value = 5;
            }
          }

          // Write our offer
          ret = bpf_skb_store_bytes(skb, 282, &offer, sizeof(offer),
                                    BPF_F_RECOMPUTE_CSUM);
          if (ret != 0) {
            bpf_printk("error %d", ret);
            return 0;
          }

          if (isIngress == 1) {
            bpf_clone_redirect(skb, skb->ifindex, BPF_F_INGRESS);
          } else {
            bpf_clone_redirect(skb, skb->ifindex, 0);
          }
          // // End the DHCP options with "255" or 0xff
          // option_value = 0xff;
          // ret = bpf_skb_store_bytes(
          //     skb, 282 + sizeof(option) + sizeof(__u8) +
          //     sizeof(option_value), &option_value, sizeof(option_value),
          //     BPF_F_RECOMPUTE_CSUM);
          // if (ret != 0) {
          //   bpf_printk("error %d", ret);
          //   return 0;
          // }
        }
        break;
        return TC_ACT_OK;
      }

      // //Get a pointer to the start of the DNS query
      // void *query_start = (void *)dns_hdr + sizeof(struct dns_hdr);

      // struct dns_query q;
      // int query_length = 0;
      // query_length = parse_query(skb, query_start, &q);
      // if (query_length < 1)
      //     {
      //         return 0;
      //     }
      // //bpf_printk("%u %s %u", query_length, q.name, sizeof(q.name));
      // if (bpf_strcmplength(q.name, "github.com", query_length) == 0) {
      //     bpf_printk("woo");
      // }
    }
  }
  return 0;
}

// eBPF hooks - This is where the magic happens!
SEC("tc_in")
int tc_ingress(struct __sk_buff *skb) { return read_dhcp(skb, 1); }

SEC("tc_egress")
int tc_egress_(struct __sk_buff *skb) { return read_dhcp(skb, 0); }