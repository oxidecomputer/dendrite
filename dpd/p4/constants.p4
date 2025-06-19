// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

const bit<16> L2_ISOLATED_FLAG = 0x8000;

// TODO: these all need to be bigger. Early experimentation is showing that this
// is going to need to come either through ATCAM/ALPM or code restructuring.
const int IPV4_NAT_TABLE_SIZE       = 1024; // nat routing table
const int IPV6_NAT_TABLE_SIZE       = 1024; // nat routing table
const int IPV4_LPM_SIZE             = 8192; // ipv4 forwarding table
const int IPV6_LPM_SIZE             = 1024; // ipv6 forwarding table
const int IPV4_ARP_SIZE             = 512;  // arp cache
const int IPV6_NEIGHBOR_SIZE        = 512;  // ipv6 neighbor cache
const int SWITCH_IPV4_ADDRS_SIZE    = 512;  // ipv4 addrs assigned to our ports
const int SWITCH_IPV6_ADDRS_SIZE    = 512;  // ipv6 addrs assigned to our ports
const int IPV4_MULTICAST_TABLE_SIZE = 1024; // multicast routing table(s) for IPv4
const int IPV6_MULTICAST_TABLE_SIZE = 1024; // multicast routing table(s) for IPv6

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
const bit<32> SVC_COUNTER_MAX = 5;

/* Encapped Multicast Tags */
const bit<2> MULTICAST_TAG_EXTERNAL = 0;
const bit<2> MULTICAST_TAG_UNDERLAY = 1;
const bit<2> MULTICAST_TAG_UNDERLAY_EXTERNAL = 2;

/* IPv6 Address Mask Constants */
const bit<128> IPV6_SCOPE_MASK = 0xffff0000000000000000000000000000;  // Match ff00::/16
const bit<128> IPV6_ULA_MASK = 0xff000000000000000000000000000000;     // Match fd00::/8

/* IPv6 Address Pattern Constants */
const bit<128> IPV6_ADMIN_LOCAL_PATTERN = 0xff040000000000000000000000000000;  // ff04::/16
const bit<128> IPV6_SITE_LOCAL_PATTERN = 0xff050000000000000000000000000000;   // ff05::/16
const bit<128> IPV6_ORG_SCOPE_PATTERN = 0xff080000000000000000000000000000;    // ff08::/16
const bit<128> IPV6_ULA_PATTERN = 0xfd000000000000000000000000000000;          // fd00::/8

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
const bit<8> DROP_MULTICAST_NO_GROUP            = 0x12;
const bit<8> DROP_MULTICAST_INVALID_MAC         = 0x13;
const bit<8> DROP_MULTICAST_CPU_COPY            = 0x14;
const bit<8> DROP_MULTICAST_SOURCE_FILTERED     = 0x15;
const bit<8> DROP_MULTICAST_PATH_FILTERED       = 0x16;
const bit<32> DROP_REASON_MAX                   = 0x17;

