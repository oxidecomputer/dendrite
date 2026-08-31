// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

// Multicast MAC prefixes per RFC 1112 and RFC 2464.
const bit<24> IPV4_MCAST_MAC_PREFIX = 0x01005e;
const bit<16> IPV6_MCAST_MAC_PREFIX = 0x3333;

// TODO: these all need to be bigger. Early experimentation is showing that this
// is going to need to come either through ATCAM/ALPM or code restructuring.
const int IPV4_NAT_TABLE_SIZE       = 1024; // nat routing table
const int IPV6_NAT_TABLE_SIZE       = 1024; // nat routing table
const int IPV4_LPM_SIZE             = 8192; // ipv4 forwarding table
const int IPV6_LPM_SIZE             = 8192; // ipv6 forwarding table
// v4 compound TTL key (forward + ttl_exceeded) keeps per-target TTL
// dispatch for mixed-ECMP support. v6 inlines TTL=1 to save a stage and
// uses 1 entry per logical route.
const int FWD_ENTRIES_PER_ROUTE_V4  = 2;
const int IPV4_ARP_SIZE             = 512;  // arp cache
const int IPV6_NEIGHBOR_SIZE        = 512;  // ipv6 neighbor cache
const int SWITCH_IPV4_ADDRS_SIZE    = 512;  // ipv4 addrs assigned to our ports
const int SWITCH_IPV6_ADDRS_SIZE    = 512;  // ipv6 addrs assigned to our ports
#ifdef MULTICAST
// Per-table sizes. Each mcast lookup is sized to its own workload rather
// than a shared global ceiling, letting p4c's table placement co-locate
// small lookups with other tables in the same stage.
//
// Every overlay group has a 1:1 mapping to an underlay group (see RFD 488,
// section MRIB Population). Overlay addresses are v4 or v6, underlay addresses
// are always v6 in the admin-local scope (ff04::/16). Omicron allocates
// underlay groups from ff04::/64 within that scope. The ingress tables key on
// the overlay address, the replication table keys on the underlay address.
//
// Today's workloads are predominantly v4 overlay multicast. The v6 ingress
// and router tables are sized for symmetry and for the admin-scoped
// overlay-to-underlay mapping, not against a v6 customer workload model.
// MCAST_REPLICATION_IPV6_SIZE bounds the number of distinct underlay v6
// destination addresses installable in mcast_replication_ipv6. The action
// hands the packet to the Tofino PRE (mcast_grp_a/b, rid, exclusion ids),
// which performs the actual replication.
const int INGRESS_IPV4_MCAST_SIZE        = 2048; // v4 overlay NAT-encap lookup
const int INGRESS_IPV6_MCAST_SIZE        = 2048; // v6 overlay NAT-encap lookup
const int MCAST_ROUTER_IPV4_SIZE         = 2048; // v4 route table, matches ingress
const int MCAST_ROUTER_IPV6_SIZE         = 2048; // v6 route table, matches ingress
const int MCAST_REPLICATION_IPV6_SIZE    = 2048; // underlay v6 groups (PRE replicates)
// Source filter holds (src, dst) pairs. "Any source" groups (ASM with no
// specific sources) consume 1 entry (/0 wildcard). Groups with a specific
// source list (SSM, or ASM with INCLUDE-mode sources) consume one entry
// per source, capped at MAX_SSM_SOURCE_IPS = 32 (omicron policy). 512
// entries fits 16 fully-saturated groups or many hundreds of typical-mix
// groups.
const int MCAST_SOURCE_FILTER_IPV4_SIZE  = 512;  // v4 source filtering
const int MCAST_SOURCE_FILTER_IPV6_SIZE  = 512;  // v6 source filtering
const int MCAST_DECAP_PORTS_SIZE         = 2048; // egress decap-port bitmap
#endif /* MULTICAST */
const int ATTACHED_SUBNETS_V4_SIZE  = 512;  // external subnets mapped to instances
const int ATTACHED_SUBNETS_V6_SIZE  = 512;  // external subnets mapped to instances

const bit<8> SC_FWD_FROM_USERSPACE  = 0x00;
const bit<8> SC_FWD_TO_USERSPACE    = 0x01;
const bit<8> SC_ICMP_NEEDED         = 0x02;
const bit<8> SC_ARP_NEEDED          = 0x03;
const bit<8> SC_NEIGHBOR_NEEDED     = 0x04;
const bit<8> SC_INVALID             = 0xff;

/* flags used for per-packet-type counters */
const bit<10> PKT_RESUBMIT  = 0x300;
const bit<10> PKT_ETHER     = 0x200;
const bit<10> PKT_LLDP      = 0x100;
const bit<10> PKT_VLAN      = 0x080;
const bit<10> PKT_SIDECAR   = 0x040;
const bit<10> PKT_ICMP      = 0x020;
const bit<10> PKT_IPV4      = 0x010;
const bit<10> PKT_IPV6      = 0x008;
const bit<10> PKT_UDP       = 0x004;
const bit<10> PKT_TCP       = 0x002;
const bit<10> PKT_ARP       = 0x001;

/* Indexes into the service_ctr table */
const bit<8> SVC_COUNTER_FW_TO_USER = 0;
const bit<8> SVC_COUNTER_FW_FROM_USER = 1;
const bit<8> SVC_COUNTER_V4_PING_REPLY = 2;
const bit<8> SVC_COUNTER_V6_PING_REPLY = 3;
const bit<8> SVC_COUNTER_BAD_PING = 4;
const bit<8> SVC_COUNTER_INBOUND_LL = 5;
const bit<8> SVC_COUNTER_PASS = 6;
const bit<32> SVC_COUNTER_MAX = 7;

#ifdef MULTICAST
/* Encapped Multicast Tags */
const bit<2> MULTICAST_TAG_EXTERNAL = 0;
const bit<2> MULTICAST_TAG_UNDERLAY = 1;
const bit<2> MULTICAST_TAG_UNDERLAY_EXTERNAL = 2;
const bit<2> MULTICAST_TAG_INVALID = 3;  // Sentinel for missing/invalid header
#endif /* MULTICAST */

/* IPv6 multicast scope constants (16-bit prefix for parser select) */
const bit<16> IPV6_INTERFACE_LOCAL_16 = 0xff01;   // ff01::/16
const bit<16> IPV6_LINK_LOCAL_16 = 0xff02;        // ff02::/16

#ifdef MULTICAST
/* IPv6 Address Mask and Pattern Constants */
// Reserved underlay multicast subnet (ff04::/64). This /64 within admin-local
// scope is reserved for internal underlay multicast allocation. Customer
// external groups may use other admin-local /64s (e.g., ff04:0:0:1::/64).
const bit<128> IPV6_UNDERLAY_MASK = 0xffffffffffffffff0000000000000000;  // /64 prefix mask
const bit<128> IPV6_UNDERLAY_MULTICAST_PATTERN = 0xff040000000000000000000000000000;  // ff04::/64
#endif /* MULTICAST */

/* Reasons a packet may be dropped by the p4 pipeline */
const bit<8> DROP_IPV4_SWITCH_ADDR_MISS         = 0x01;
const bit<8> DROP_IPV6_SWITCH_ADDR_MISS         = 0x02;
const bit<8> DROP_BAD_PING                      = 0x03;
const bit<8> DROP_NAT_HEADER_ERROR              = 0x04;
const bit<8> DROP_ARP_NULL                      = 0x05;
const bit<8> DROP_ARP_MISS                      = 0x06;
const bit<8> DROP_NDP_NULL                      = 0x07;
const bit<8> DROP_NDP_MISS                      = 0x08;
const bit<8> DROP_MULTICAST_TO_LOCAL_INTERFACE	= 0x09;
const bit<8> DROP_IPV4_CHECKSUM_ERR             = 0x0A;
const bit<8> DROP_IPV4_TTL_INVALID              = 0x0B;
const bit<8> DROP_IPV4_TTL_EXCEEDED             = 0x0C;
const bit<8> DROP_IPV6_TTL_INVALID              = 0x0D;
const bit<8> DROP_IPV6_TTL_EXCEEDED             = 0x0E;
const bit<8> DROP_IPV4_UNROUTEABLE              = 0x0F;
const bit<8> DROP_IPV6_UNROUTEABLE              = 0x10;
const bit<8> DROP_NAT_INGRESS_MISS              = 0x11;
const bit<8> DROP_NAT_EGRESS_BLOCKED            = 0x12;
const bit<8> DROP_MULTICAST_INVALID_MAC         = 0x14;
const bit<8> DROP_GENEVE_OPTIONS_TOO_LONG       = 0x18;
const bit<8> DROP_GENEVE_OPTION_MALFORMED       = 0x19;
const bit<8> DROP_GENEVE_OPTION_UNKNOWN         = 0x1A;
const bit<8> DROP_SCTP                          = 0x1B;

#ifdef MULTICAST
/* Multicast-only drop reasons. Codes 0x13 and 0x15-0x17 are skipped without
 * MULTICAST. Values are preserved across builds to keep drop codes stable.
 */
const bit<8> DROP_MULTICAST_NO_GROUP            = 0x13;
const bit<8> DROP_MULTICAST_CPU_COPY            = 0x15;
const bit<8> DROP_MULTICAST_SOURCE_FILTERED     = 0x16;
const bit<8> DROP_MULTICAST_PATH_FILTERED       = 0x17;
#endif /* MULTICAST */

// MAX(DROP_xxx) + 1
const bit<32> DROP_REASON_MAX                   = 0x1C;
