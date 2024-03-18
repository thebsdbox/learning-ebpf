#include "../headers/vmlinux.h"

#define DHCP_BOOTREQUEST 1
#define DHCP_BOOTREPLY 2

#define DHCP_OPTION_MAGIC_NUMBER (0x63825363)

typedef struct {
  __u32 address;
  __u8 dhcp_state;
} dhcp_entry;

// DHCP Message
struct dhcp_message {
  u_char dp_op;                 /* packet opcode type */
  u_char dp_htype;              /* hardware addr type */
  u_char dp_hlen;               /* hardware addr length */
  u_char dp_hops;               /* gateway hops */
  u_int32_t dp_xid;             /* transaction ID */
  u_int16_t dp_secs;            /* seconds since boot began */
  u_int16_t dp_flags;           /* flags */
  __u32 dp_ciaddr;              /* client IP address */
  __u32 dp_yiaddr;              /* 'your' IP address */
  __u32 dp_siaddr;              /* server IP address */
  __u32 dp_giaddr;              /* gateway IP address */
  u_char dp_chaddr[6];          /* client hardware address */
  u_char dp_chaddr_padding[10]; /* client hardware address padding*/
  u_char dp_sname[64];          /* server host name */
  u_char dp_file[128];          /* boot file name */
  __u32 magic;                  /* magic number */
} __attribute__((packed));

typedef struct {
  // option 53
  __u8 option_message_type;
  __u8 option_message_type_len;
  __u8 option_message_value;

  // option 1
  __u8 option_subnet_mask;
  __u8 option_subnet_mask_len;
  __u32 option_subnet_mask_value;

  // option 3
  __u8 option_router;
  __u8 option_router_len;
  __u32 option_router_value;

  // option 58
  __u8 option_renew_time;
  __u8 option_renew_time_len;
  __u32 option_renew_time_value;

  // option 59
  __u8 option_rebind_time;
  __u8 option_rebind_time_len;
  __u32 option_rebind_time_value;

  // option 51
  __u8 option_lease_time;
  __u8 option_lease_time_len;
  __u32 option_lease_time_value;

  // option 54
  __u8 option_dhcp_id;
  __u8 option_dhcp_id_len;
  __u32 option_dhcp_id_value;

  // end
  __u8 end;
} dhcp_offer;

// options

typedef struct {
  __u8 code;
  __u8 length;
} dhcp_option;
