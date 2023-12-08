// +build ignore

#include "../headers/vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <string.h>

char __license[] SEC("license") = "GPL";

#define TC_ACT_OK 0
#define ETH_P_IP 0x0800 /* Internet Protocol packet */
#define ETH_HLEN 14 /*Ethernet Header Length */

#define max_path_len 20

static inline int is_http(struct __sk_buff *skb, __u64 nh_off);
static inline int bpf_strcmplength(char *s1, char *s2, u32 n);
// static inline int bpf_strncmpoffset(char *s1, char *s2, u32 n, u32 o);

struct url_path {
  __u8 path_len;
  __u8 path[max_path_len]; // This should be a char but code generation between here and Go..
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __type(key, char[max_path_len]);
  __type(value, struct url_path);
}
url_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __type(key, __u16);
  __type(value, __u16);
}
redirect_map SEC(".maps");

static inline void set_tcp_dport(struct __sk_buff *skb, int nh_off,
                                 __u16 old_port, __u16 new_port)
{
    bpf_l4_csum_replace(skb, nh_off + offsetof(struct tcphdr, check),
                        old_port, new_port, sizeof(new_port));
    bpf_skb_store_bytes(skb, nh_off + offsetof(struct tcphdr, dest),
                        &new_port, sizeof(new_port), 0);
}

static inline void set_tcp_sport(struct __sk_buff *skb, int nh_off,
                                 __u16 old_port, __u16 new_port)
{
    bpf_l4_csum_replace(skb, nh_off + offsetof(struct tcphdr, check),
                        old_port, new_port, sizeof(new_port));
    bpf_skb_store_bytes(skb, nh_off + offsetof(struct tcphdr, source),
                        &new_port, sizeof(new_port), 0);
}



SEC("tc_in")
int tc_ingress(struct __sk_buff * skb) {
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
        if (is_http(skb, nh_off) == 1) {
            bpf_printk("Found what we were looking for"); 
        }
    }

    return TC_ACT_OK;
}

SEC("tc_egress")
int tc_egress_(struct __sk_buff *skb)
{
    struct iphdr ip;
    struct tcphdr tcp;
    if (0 != bpf_skb_load_bytes(skb, sizeof(struct ethhdr), &ip, sizeof(struct iphdr)))
    {
        bpf_printk("bpf_skb_load_bytes iph failed");
        return TC_ACT_OK;
    }

    if (0 != bpf_skb_load_bytes(skb, sizeof(struct ethhdr) + (ip.ihl << 2), &tcp, sizeof(struct tcphdr)))
    {
        bpf_printk("bpf_skb_load_bytes eth failed");
        return TC_ACT_OK;
    }

    unsigned int src_port = bpf_ntohs(tcp.source);
    unsigned int dst_port = bpf_ntohs(tcp.dest);

    if (src_port == 80 || dst_port == 80 || src_port == 8090 || dst_port == 8090)
        bpf_printk("-> %pI4:%u -> %pI4:%u", &ip.saddr, src_port, &ip.daddr, dst_port);

    if (src_port != 8090)
        return TC_ACT_OK;
    if (tcp.rst) {
        bpf_printk("-> sending a reset");
        //__u16 port = 0;
        int update = bpf_map_update_elem(&redirect_map, &dst_port, &src_port, BPF_ANY);
        if (update !=0) {
            bpf_printk("-> couldnt update map");
        }

    }


    set_tcp_sport(skb, ETH_HLEN + sizeof(struct iphdr), bpf_htons(8090), bpf_htons(80));

    return TC_ACT_OK;
}


static inline int is_http(struct __sk_buff *skb, __u64 nh_off) {
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
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
    unsigned int src_port = bpf_ntohs(tcph->source);
    __u16 dst_port = bpf_ntohs(tcph->dest);

    //if (dst_port == 80) {
        __u16 *redirect = bpf_map_lookup_elem(&redirect_map, &src_port);
        if (redirect) {
            bpf_printk("<- hack that header for %d", dst_port);
            set_tcp_dport(skb, ETH_HLEN + sizeof(struct iphdr), bpf_htons(80), bpf_htons(8090));
            return TC_ACT_OK;
        }
    //}
    //     dst_port = bpf_htons(dst_port);
    //     redirect = bpf_map_lookup_elem(&redirect_map, &dst_port);
    //     if (redirect) {
    //         bpf_printk("INGRESS - hack that shit for %d", dst_port);
    //     }
    // }

    if (src_port == 80 || dst_port == 80 || src_port == 8090 || dst_port == 8090 )
        bpf_printk("<- %pI4:%u -> %pI4:%u", iph->saddr, src_port, iph->daddr, dst_port);

    tcp_hlen = tcph->doff << 2;
    poffset = ETH_HLEN + ip_hlen + tcp_hlen;
    plength = ip_total_length - ip_hlen - tcp_hlen;
    if (plength >= 7) {

        // Room to store 80 bytes of data from the packet
        char pdata[60];

        // Load data from the socket buffer, poffset starts at the end of the TCP Header
        int ret = bpf_skb_load_bytes(skb, poffset, pdata, 60);
        if (ret != 0) {
           return 0;
        }

        // Look for a GET request
        if (bpf_strcmplength(pdata, "GET", 3) == 0) {
            
            // Debug statements
            //bpf_printk("%s", pdata);
            //bpf_printk("packet length %d, data offset %d, data size %d", ip_total_length, poffset, plength);

            char path[max_path_len];
            memset(&path, 0, sizeof(path));

            int path_len = 0;
 
            // Find the request URI (starts at offset 4), ends with a space
            for (int i = 4; i < sizeof(pdata) ; i++)
            {
                if (pdata[i] != ' ') {
                    path[i-4] = pdata[i];
                } else {
                    path[i-4] = '\0';
                    path_len = i-4;
                    break;
                }
            }
            // Print out the Get request path
            bpf_printk("<- incoming path [%s], length [%d]", path, path_len);
            struct url_path *found_path = bpf_map_lookup_elem(&url_map, path);
            if (found_path > 0) {
                //set_tcp_dport(skb, ETH_HLEN + sizeof(struct iphdr), bpf_htons(80), bpf_htons(8090));
                bpf_printk("Looks like we've found your path [%s]", path);
            }
        }
    }

    return 0;
}

static inline int bpf_strcmplength(char *s1, char *s2, u32 n)
{
    for (int i = 0; i < n && i < sizeof(s1) && i < sizeof(s2); i++)
    {
        if (s1[i] != s2[i])
            return s1[i] - s2[i];

        if (s1[i] == s2[i] == '\0')
            return 0;
    }

    return 0;
}

// static inline int bpf_strncmpoffset(char *s1, char *s2, u32 n, u32 o)
// {
//     for (int i = 0; i < n && i < sizeof(s1) && i < sizeof(s2); i++)
//     {
//         if (s1[i+o] != s2[i])
//             return s1[i+o] - s2[i];

//         if (s1[i+o] == s2[i] == '\0')
//             return 0;
//     }

//     return 0;
// }
