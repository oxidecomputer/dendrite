// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

struct sidecar_ingress_meta_t {
	bool ipv4_checksum_err;		// failed ipv4 checksum
	bool is_switch_address;		// destination IP was a switch port
	bool is_mcast;				// packet is multicast
	bool allow_source_mcast;	// allowed to be sent from a source address for SSM
	bool is_link_local_mcast;	// packet is a IPv6 link-local multicast packet
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

	// Used for responding to pings
	mac_addr_t orig_src_mac;	// source mac address before rewriting
	ipv4_addr_t orig_src_ipv4;	// original ipv4 source
	ipv4_addr_t orig_dst_ipv4;	// original ipv4 target
}

struct sidecar_egress_meta_t {
	bit<8> drop_reason;		// reason a packet was dropped
}
