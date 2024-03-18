#include "../headers/vmlinux.h"

#define BGP_OPEN 1
#define BGP_UPDATE 2
#define BGP_NOTIFICATION 3
#define BGP_KEEPALIVE 4
#define BGP_ROUTE_REFRESH 5

struct bgp_message {
  __u8 marker[16];
  __u16 length;
  __u8 type;
};

struct bgp_open {
  __u8 version;
  __u16 myAS;
  __u16 holdTimer;
  __u32 identifier;
};
struct nlri {
  __u8 prefixlen;
  __u32 prefix;
};

typedef struct {
  __u8 prefixlen;
  __u32 prefix;
} nlri_value;

struct bgp_path_attributes {
  __u8 flags;
  __u8 type;
  __u8 len;
};

struct bgp_path_origin {
  __u8 origin;
};

struct bgp_path_as {
  __u8 type;
  __u8 lenth;
  __u32 as;
};

struct bgp_path_hop {
  __u32 hop;
};