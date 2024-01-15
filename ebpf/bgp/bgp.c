// +build ignore

#include "../headers/vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <string.h>


#pragma pack(1) 
#include "bgp.h"

char __license[] SEC("license") = "GPL";

#define TC_ACT_OK 0
#define ETH_P_IP 0x0800 /* Internet Protocol packet */
#define ETH_HLEN 14 /*Ethernet Header Length */


// static inline int bpf_strcmplength(char *s1, char *s2, u32 n);
// static inline int bpf_strncmpoffset(char *s1, char *s2, u32 n, u32 o);


// static __always_inline bool skb_revalidate_data(struct __sk_buff *skb,
//                                                 void **head, void **tail,
//                                                 const u32 offset) {
//     if (*head + offset > *tail) {
//         if (bpf_skb_pull_data(skb, offset) < 0) {
//             return false;
//         }

//         *head = (uint8_t *)(long)skb->data;
//         *tail = (uint8_t *)(long)skb->data_end;

//         if (*head + offset > *tail) {
//             return false;
//         }
//     }

//     return true;
// }

static inline int read_bgp(struct __sk_buff *skb) {
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

    if (h_proto == bpf_htons(ETH_P_IP)) {
    struct iphdr *iph = data + nh_off;

    if ((void*)(iph + 1) > data_end) {
        return 0;
    }

    if (iph->protocol != IPPROTO_TCP) {
        return 0;
    }
    __u32 tcp_hlen = 0;
    __u32 ip_hlen = 0;
    __u32 poffset = 0;
    __u32 plength = 0;
    __u32 ip_total_length = bpf_ntohs(iph->tot_len);

    ip_hlen = iph->ihl << 2;

    if (ip_hlen < sizeof(*iph)) {
        return 0;
    }
    struct tcphdr *tcph = data + nh_off + sizeof(*iph);

    if ((void*)(tcph + 1) > data_end) {
        return 0;
    }
    __u16 src_port = bpf_ntohs(tcph->source);
    __u16 dst_port = bpf_ntohs(tcph->dest);

    if (src_port == 179 || dst_port == 179) {
        tcp_hlen = tcph->doff << 2;
        poffset = ETH_HLEN + ip_hlen + tcp_hlen;
        plength = ip_total_length - ip_hlen - tcp_hlen;
        if (plength >= 18 ) { // Abitrary length, but this seems to be the minimum for a keep alive message

            struct bgp_message bgpm;
            int ret = bpf_skb_load_bytes(skb, poffset, &bgpm, sizeof(bgpm));
            if (ret != 0) {
                bpf_printk("error %d",ret);
                return 0;
            }   

            poffset += sizeof(bgpm); // remove header
            struct bgp_open open_msg;
            switch (bgpm.type)
            {
                case BGP_OPEN:
                // statements
                ret = bpf_skb_load_bytes(skb, poffset, &open_msg, sizeof(open_msg));
                if (ret != 0) {
                    bpf_printk("error %d",ret);
                    return 0;
                }
                bpf_printk("BGP open message AS: %d, identifier: %pI4  ", bpf_ntohs(open_msg.myAS), &open_msg.identifier);
                break;

                case BGP_UPDATE:
                // statements
                bpf_printk("BGP update length %d", bpf_ntohs(bgpm.length));
                //__u16 remainingdata = bpf_ntohs(bgpm.length); 
                //remainingdata -= sizeof(bgpm); // remove header
                __u16 withdrawnlen;
                int ret = bpf_skb_load_bytes(skb, poffset, &withdrawnlen, sizeof(withdrawnlen));
                if (ret != 0) {
                    bpf_printk("error %d",ret);
                    return 0;
                }
                //remainingdata -= sizeof(withdrawnlen) + bpf_ntohs(withdrawnlen); // remove withdrawn routes
                bpf_printk("BGP withdrawn routes %d", bpf_ntohs(withdrawnlen));
                poffset += sizeof(withdrawnlen) + bpf_ntohs(withdrawnlen);
                ret = bpf_skb_load_bytes(skb, poffset, &withdrawnlen, sizeof(withdrawnlen));
                if (ret != 0) {
                    bpf_printk("error %d",ret);
                    return 0;
                }
                
                bpf_printk("BGP path flags size %d, will attempt to parse the first three", bpf_ntohs(withdrawnlen));
                struct bgp_path_attributes bgp_path;

                poffset += sizeof(withdrawnlen);// + bpf_ntohs(withdrawnlen);
                __u32 pathOffset = poffset;
                ret = bpf_skb_load_bytes(skb, pathOffset, &bgp_path, sizeof(bgp_path));
                if (ret != 0) {
                    bpf_printk("error %d",ret);
                    return 0;
                }
                bpf_printk("BGP Origin -> %d / options length %d", bgp_path.type, bgp_path.len);

                // Time for some hideous grossness, but I can't be bothered with loops in eBPF today
                __u16 lencounter = withdrawnlen;
                lencounter -= sizeof(bgp_path) + bgp_path.len; // shrink the amount of data remaining
                if (lencounter != 0) {
                    pathOffset += sizeof(bgp_path) + bgp_path.len;
                    ret = bpf_skb_load_bytes(skb, pathOffset, &bgp_path, sizeof(bgp_path));
                    if (ret != 0) {
                        bpf_printk("error %d",ret);
                        return 0;
                    }
                    bpf_printk("BGP Origin -> %d / options length %d", bgp_path.type, bgp_path.len);

                    // TODO: this is where we parse the incoming AS
                    struct  bgp_path_as bgp_as;
                    pathOffset += sizeof(bgp_path);
                    ret = bpf_skb_load_bytes(skb, pathOffset, &bgp_as, sizeof(bgp_as));
                    if (ret != 0) {
                        bpf_printk("error %d",ret);
                        return 0;
                    }
                    bpf_printk("Found the AS %u %u %u", bgp_as.type, bgp_as.lenth, bpf_ntohl(bgp_as.as));

                    lencounter -= sizeof(bgp_path) + bgp_path.len; // shrink the amount of data remaining
                    if (lencounter != 0) {
                        pathOffset += bgp_path.len;
                        ret = bpf_skb_load_bytes(skb, pathOffset, &bgp_path, sizeof(bgp_path));
                        if (ret != 0) {
                            bpf_printk("error %d",ret);
                            return 0;
                        }
                            bpf_printk("BGP Origin -> %d / options length %d", bgp_path.type, bgp_path.len);
                    }
                }
                poffset += bpf_ntohs(withdrawnlen); // Skip all options
                //bpf_printk("Remaining data %d", remainingdata);
                struct nlri nlri;
                ret = bpf_skb_load_bytes(skb, poffset, &nlri, sizeof(nlri));
                if (ret != 0) {
                    bpf_printk("error %d",ret);
                    return 0;
                }
                bpf_printk("Found NLRI info -> %pI4 / %d", &nlri.prefix, nlri.prefixlen);
                
                break;
                case BGP_NOTIFICATION:
                bpf_printk("BGP notification");

                break;
                case BGP_KEEPALIVE:
                bpf_printk("BGP keep alive");
                break;

                default:
                // default statements
                break;
                }
            }
        }
    }   
    return 0;
}


SEC("tc_in")
int tc_ingress(struct __sk_buff * skb) {
    return read_bgp(skb);

}

SEC("tc_egress")
int tc_egress_(struct __sk_buff *skb)
{
    return read_bgp(skb);
}
