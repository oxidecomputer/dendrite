const bit<16> L2_ISOLATED_FLAG = 0x8000;
#define IS_SERVICE(p) ((p) == USER_SPACE_SERVICE_PORT)

//TODO these all need to be bigger. Early experimentation is showing that this
//is going to need to come either through ATCAM/ALPM or code restructuring.
const int IPV4_NAT_TABLE_SIZE		= 1024; // nat routing table
const int IPV6_NAT_TABLE_SIZE		= 1024; // nat routing table
const int IPV4_LPM_SIZE			= 4096; // ipv4 forwarding table
const int IPV6_LPM_SIZE			= 1024; // ipv6 forwarding table

const int IPV4_ARP_SIZE			= 512;  // arp cache
const int IPV6_NEIGHBOR_SIZE		= 512;  // ipv6 neighbor cache
const int SWITCH_IPV4_ADDRS_SIZE	= 512;  // ipv4 addrs assigned to our ports
const int SWITCH_IPV6_ADDRS_SIZE	= 512;  // ipv6 addrs assigned to our ports

const bit<8> SC_FWD_FROM_USERSPACE	= 0x00;
const bit<8> SC_FWD_TO_USERSPACE	= 0x01;
const bit<8> SC_ICMP_NEEDED		= 0x02;
const bit<8> SC_ARP_NEEDED		= 0x03;
const bit<8> SC_NEIGHBOR_NEEDED		= 0x04;
const bit<8> SC_INVALID			= 0xff;

/* flags used for per-packet-type counters */
const bit<10> PKT_ETHER		= 0x200;
const bit<10> PKT_LLDP		= 0x100;
const bit<10> PKT_VLAN		= 0x080;
const bit<10> PKT_SIDECAR	= 0x040;
const bit<10> PKT_ICMP		= 0x020;
const bit<10> PKT_IPV4		= 0x010;
const bit<10> PKT_IPV6		= 0x008;
const bit<10> PKT_UDP		= 0x004;
const bit<10> PKT_TCP		= 0x002;
const bit<10> PKT_ARP		= 0x001;

/* Indexes into the service_ctr table */
const bit<8> SVC_COUNTER_FW_TO_USER = 0;
const bit<8> SVC_COUNTER_FW_FROM_USER = 1;
const bit<8> SVC_COUNTER_V4_PING_REPLY = 2;
const bit<8> SVC_COUNTER_V6_PING_REPLY = 3;
const bit<8> SVC_COUNTER_BAD_PING = 4;
const bit<32> SVC_COUNTER_MAX = 5;

/* Reasons a packet may be dropped by the p4 pipeline */
const bit<8> DROP_IPV4_SWITCH_ADDR_MISS		= 0x01;
const bit<8> DROP_IPV6_SWITCH_ADDR_MISS		= 0x02;
const bit<8> DROP_BAD_PING			= 0x03;
const bit<8> DROP_NAT_HEADER_ERROR		= 0x04;
const bit<8> DROP_ARP_NULL			= 0x05;
const bit<8> DROP_ARP_MISS			= 0x06;
const bit<8> DROP_NDP_NULL			= 0x07;
const bit<8> DROP_NDP_MISS			= 0x08;
const bit<8> DROP_MULTICAST_TO_LOCAL_INTERFACE	= 0x09;
const bit<8> DROP_IPV4_CHECKSUM_ERR		= 0x0A;
const bit<8> DROP_IPV4_TTL_INVALID		= 0x0B;
const bit<8> DROP_IPV4_TTL_EXCEEDED		= 0x0C;
const bit<8> DROP_IPV6_TTL_INVALID		= 0x0D;
const bit<8> DROP_IPV6_TTL_EXCEEDED		= 0x0E;
const bit<8> DROP_IPV4_UNROUTEABLE		= 0x0F;
const bit<8> DROP_IPV6_UNROUTEABLE		= 0x10;
const bit<8> DROP_NAT_INGRESS_MISS		= 0x11;
const bit<32> DROP_REASON_MAX			= 0x12;
