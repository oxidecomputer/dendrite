// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

// Guard against compiler bug: RemoveMetadataInits strips explicit `= false`
// initializations, assuming parser will zero-init the PHV container.
// ComputeInitZeroContainers only marks containers for zero-init if the field
// is actually used in the parser, not just initialized. These assumptions are
// incompatible: fields initialized but only used in MAU get stale data.
// See: https://github.com/oxidecomputer/tofino-p4c/blob/ry/upstream-merge/rydocs/tofino-metadata-corruption.md
@pa_no_init("ingress", "meta.service_routed")
@pa_no_init("ingress", "meta.nat_egress_hit")
@pa_no_init("ingress", "meta.nat_ingress_hit")
@pa_no_init("ingress", "meta.nat_ingress_port")
@pa_no_init("ingress", "meta.encap_needed")
@pa_no_init("ingress", "meta.icmp_recalc")
@pa_no_init("ingress", "meta.allow_source_mcast")
@pa_no_init("ingress", "meta.resolve_nexthop")
@pa_no_init("ingress", "meta.nexthop_is_v6")
@pa_no_init("ingress", "meta.route_ttl_is_1")

// Force fields out of mocha containers into normal containers. Mocha containers
// only support whole-container-set operations, so isolated fields can have
// their other bits corrupted by stale data from previous packets.
//
// Without these pragmas the compiler may pack small metadata fields into mocha
// containers alongside unrelated fields. A whole-container write to one field
// then clobbers the others. The risk is highest for 1-bit booleans and fields
// with long liverange gaps between set and use.
//
// Both builds share ipv4_checksum_err: confirmed allocated to mocha MH0 where
// it shared a container with pkt_type, risking false checksum-error drops.
@pa_container_type("ingress", "meta.ipv4_checksum_err", "normal")

#ifdef MULTICAST
// Ingress fields needed for NAT encapsulation and checksum computation.
@pa_container_type("ingress", "meta.nat_ingress_tgt", "normal")
@pa_container_type("ingress", "meta.nat_geneve_vni", "normal")
@pa_container_type("ingress", "meta.icmp_csum", "normal")
@pa_container_type("ingress", "meta.body_checksum", "normal")
@pa_container_type("ingress", "meta.orig_src_mac", "normal")
@pa_container_type("ingress", "meta.orig_src_ipv4", "normal")
@pa_container_type("ingress", "meta.drop_reason", "normal")
@pa_container_type("ingress", "meta.l4_dst_port", "normal")
@pa_container_type("ingress", "meta.nat_inner_mac", "normal")
// Carried over from non-MULTICAST build. Without explicit pragmas these
// fields were only protected by incidental co-location with deparsed bridge
// header fields in the same container, which is fragile across compiler
// versions and PHV pressure changes.
@pa_container_type("ingress", "meta.service_routed", "normal")
@pa_container_type("ingress", "meta.l4_src_port", "normal")
@pa_container_type("ingress", "meta.icmp_recalc", "normal")
@pa_container_type("ingress", "meta.nat_ingress_csum", "normal")
// Egress bridge header fields crossing the ingress/egress boundary.
@pa_container_type("egress", "meta.bridge_hdr.ingress_port", "normal")
@pa_container_type("egress", "meta.bridge_hdr.is_mcast_routed", "normal")
// Egress fields set by multicast table actions and consumed later in the
// pipeline. drop_reason was confirmed allocated to mocha MH9 where it
// shared a container with drop_ctl. ipv4_checksum_recalc is a 1-bit field
// at high risk of mocha packing.
@pa_container_type("egress", "meta.vlan_id", "normal")
@pa_container_type("egress", "meta.port_number", "normal")
@pa_container_type("egress", "meta.ipv4_checksum_recalc", "normal")
@pa_container_type("egress", "meta.drop_reason", "normal")
#else
@pa_container_type("ingress", "meta.service_routed", "normal")
@pa_container_type("ingress", "meta.nexthop", "normal")
@pa_container_type("ingress", "meta.l4_src_port", "normal")
@pa_container_type("ingress", "meta.icmp_recalc", "normal")
@pa_container_type("ingress", "meta.nat_ingress_csum", "normal")
@pa_container_type("ingress", "meta.drop_reason", "normal")
#endif

/* Flexible bridge header for passing metadata between ingress and egress
 * pipelines.
 */
@flexible
header bridge_h {
	PortId_t ingress_port;		// 9 bits
	bool is_mcast_routed;		// 1 bit: packet was routed to multicast (PRE)
	bit<6> reserved;		// 6 bits: padding to 16-bit boundary
}

struct sidecar_ingress_meta_t {
	bool dropped;			// has packet been dropped
	bool ipv4_checksum_err;		// failed ipv4 checksum
	bool is_switch_address;		// destination IP was a switch port
	bool is_mcast;			// packet is multicast
	bool allow_source_mcast;	// allowed to be sent from a source address for SSM
	bool is_link_local_mcastv6;	// packet is a IPv6 link-local multicast packet
	bool service_routed;		// routed to or from a service routine
	bool nat_egress_hit;		// NATed packet from guest -> uplink
	bool nat_ingress_hit;		// NATed packet from uplink -> guest
	bool nat_ingress_port;		// This port accepts only NAT traffic
	bool encap_needed;
	bool resolve_nexthop;		// signals nexthop needs to be resolved
	bool route_ttl_is_1;		// TTL/hop_limit equals 1 (for route lookup)
	bool nexthop_is_v6;		// true when nexthop is IPv6
	ipv6_addr_t nexthop;		// next hop address; IPv4 uses low bits
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

// Unified route result struct for both Router4 and Router6.
// A single instance is allocated in L3Router and passed to both
// controls, forcing the compiler to use the same PHV allocation
// and preventing liverange divergence under high PHV pressure.
struct route_result_t {
	/* Did we successfully look up the route in the table? */
	bool is_hit;

	/*
	 * A hash of the (address,port) fields, which is used to choose between
	 * multiple potential routes.
	 */
	bit<8> ecmp_hash;

	/* Index into the target table of the first potential route */
	bit<16> idx;
	/* Number of consecutive slots containing potential routes */
	bit<8> slots;
	/* Which of those routes we should select, based the flow hash */
	bit<16> slot;
}
