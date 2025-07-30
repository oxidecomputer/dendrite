// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

/* Flexible bridge header for passing metadata between ingress and egress
 * pipelines.
 */
@flexible
header bridge_h {
	PortId_t ingress_port;
}

struct sidecar_ingress_meta_t {
	bool ipv4_checksum_err;		// failed ipv4 checksum
	bool is_switch_address;		// destination IP was a switch port
	bool is_mcast;			// packet is multicast
	bool is_valid;			// packet is valid
	bool allow_source_mcast;	// allowed to be sent from a source address for SSM
	bool is_link_local_mcastv6;	// packet is a IPv6 link-local multicast packet
	bool service_routed;		// routed to or from a service routine
	bool nat_egress_hit;		// NATed packet from guest -> uplink
	bool nat_ingress_hit;		// NATed packet from uplink -> guest
	bool nat_ingress_port;		// This port accepts only NAT traffic
	ipv4_addr_t nexthop_ipv4;	// ip address of next router
	ipv6_addr_t nexthop_ipv6;	// ip address of next router
	bit<10> pkt_type;
	bit<8> drop_reason;		// reason a packet was dropped
	bit<16> l4_src_port;		// tcp or udp destination port
	bit<16> l4_dst_port;		// tcp or udp destination port
	ipv6_addr_t nat_ingress_tgt;	// target address for NAT ingress
	mac_addr_t nat_inner_mac;	// inner mac address for NAT ingress
	geneve_vni_t nat_geneve_vni;	// VNI for NAT ingress

	// If we modify an ICMP header, we need to recalculate its checksum.
	// To do the math, we need the original checksum.
	bool icmp_recalc;
	bit<16> icmp_csum;

	// Used when calculating outer UDP checksum for encapsulated NAT
	// ingress packets
	bit<16> body_checksum;		// residual csum for packet body
	bit<16> l4_length;

	mac_addr_t orig_src_mac;	// source mac address before rewriting
	ipv4_addr_t orig_src_ipv4;	// original ipv4 source
	ipv4_addr_t orig_dst_ipv4;	// original ipv4 target

	bridge_h bridge_hdr;		// bridge header

	bit<16> nat_ingress_csum;
}

struct sidecar_egress_meta_t {
	bit<8> drop_reason;	// reason a packet was dropped
	bridge_h bridge_hdr;	// bridge header

	// 256-bit port bitmap separated across 8 x 32-bit values
	bit<32> decap_ports_0;	// Ports 0-31
	bit<32> decap_ports_1;	// Ports 32-63
	bit<32> decap_ports_2;	// Ports 64-95
	bit<32> decap_ports_3;	// Ports 96-127
	bit<32> decap_ports_4;	// Ports 128-159
	bit<32> decap_ports_5;	// Ports 160-191
	bit<32> decap_ports_6;	// Ports 192-223
	bit<32> decap_ports_7;	// Ports 224-255

	bit<32> bitmap_result;		// result of decap bitmap
	bool ipv4_checksum_recalc; 	// recalc checksum for IPv4
	bit<12> vlan_id;		// VLAN ID for the packet
	bit<8> port_number; 		// Port number for the outgoing port (0-255)
}

struct route4_result_t {
	/*
	 * The result of the multistage route selection process is an egress
	 * port and a nexthop address
	 */
	ipv4_addr_t nexthop;
	PortId_t port;

	/* Did we successfully look up the route in the table? */
	bool is_hit;

	/*
	 * A hash of the (address,port) fields, which is used to choose between
	 * multiple potential routes.
	 */
	bit<8> hash;

	/* Index into the target table of the first potential route */
	bit<16> idx;
	/* Number of consecutive slots containing potential routes */
	bit<8> slots;
	/* Which of those routes we should select, based the flow hash */
	bit<16> slot;
}

struct route6_result_t {
	ipv6_addr_t nexthop;
	PortId_t port;
	bool is_hit;
}
