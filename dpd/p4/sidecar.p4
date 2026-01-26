// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

#if __TARGET_TOFINO__ == 2
#include <t2na.p4>
const bit<9> USER_SPACE_SERVICE_PORT = 0;
#else
#include <tna.p4>
const bit<9> USER_SPACE_SERVICE_PORT = 192;
#endif

#include <headers.p4>
#include <metadata.p4>
#include <constants.p4>
#include <parser.p4>

// This is the port that we use to send packets to user space.
#define IS_SERVICE(p) ((p) == USER_SPACE_SERVICE_PORT)

// Includes the checksum for the original data, the geneve header, the
// outer udp header, and the outer ipv6 pseudo-header.
// NOTE: safe to include geneve oxg_ext_tag here (via nat_ingress_csum)
// as it is filled unconditionally on nat_ingress, and nat_checksum is only
// computed on nat_ingress.
#define COMMON_FIELDS                \
    meta.body_checksum,              \
    hdr.inner_eth,                   \
    hdr.geneve,                      \
    meta.nat_ingress_csum,           \
    hdr.udp.src_port,                \
    hdr.udp.dst_port,                \
    hdr.udp.hdr_length,              \
    (bit<16>)hdr.ipv6.next_hdr,      \
    hdr.ipv6.src_addr,               \
    hdr.ipv6.dst_addr,               \
    hdr.ipv6.payload_len

// Includes the final bit of the inner ipv4 pseudo-header and the inner ipv4
// header
#define IPV4_FIELDS         \
    meta.l4_length,         \
    hdr.inner_ipv4

// Includes the inner ipv6 header
#define IPV6_FIELDS         \
    hdr.inner_ipv6

// This control handles the calculation of Layer 4 payload length
// by subtracting the IPv4 header length from the total packet length.
//
// This is accomplished using a table-based approach due to P4/Tofino limitations:
// 1. We can't directly subtract a variable value (the IPv4 header length)
// 2. Instead, we use a table with IHL (IP Header Length) as the key
// 3. For each IHL value, we add a negative constant that achieves the subtraction
//    (e.g., adding 0xffec, which is -20 in two's complement, subtracts 20 bytes)
control CalculateIPv4Len(
	inout sidecar_headers_t hdr,
	inout sidecar_ingress_meta_t meta
) {
	// Action to add (or effectively subtract) a value from IPv4 total length
	action add(bit<16> a) {
		meta.l4_length = hdr.ipv4.total_len + a;
	}

	action invert() {
		meta.l4_length = ~meta.l4_length;
	}

	// Table maps IPv4 header length (IHL) to the appropriate "add" action
	// with the correct negative constant
	table ipv4_set_len {
		key = { hdr.ipv4.ihl : exact; }
		actions = { add; }

		const entries = {
			(5) : add(0xffec);  // Subtract 20 bytes (standard header)
			(6) : add(0xffe8);  // Subtract 24 bytes
			(7) : add(0xffe4);  // Subtract 28 bytes
			(8) : add(0xffe0);  // Subtract 32 bytes
			(9) : add(0xffdc);  // Subtract 36 bytes
			(10): add(0xffd8);  // Subtract 40 bytes
			(11): add(0xffd4);  // Subtract 44 bytes
			(12): add(0xffd0);  // Subtract 48 bytes
			(13): add(0xffcc);  // Subtract 52 bytes
			(14): add(0xffc8);  // Subtract 56 bytes
			(15): add(0xffc4);  // Subtract 60 bytes
		}

		const size = 16;
	}

	apply {
		ipv4_set_len.apply();
		invert();
	}
}

control Filter(
	inout sidecar_headers_t hdr,
	inout sidecar_ingress_meta_t meta,
	in ingress_intrinsic_metadata_t ig_intr_md
) {
	DirectCounter<bit<32>>(CounterType_t.PACKETS_AND_BYTES) ipv4_ctr;
	DirectCounter<bit<32>>(CounterType_t.PACKETS_AND_BYTES) ipv6_ctr;
#ifdef MULTICAST
	Counter<bit<32>, PortId_t>(512, CounterType_t.PACKETS) drop_mcast_ctr;
	bit<16> mcast_scope;
#endif /* MULITCAST */

	action dropv4() {
		meta.drop_reason = DROP_IPV4_SWITCH_ADDR_MISS;
		meta.dropped = true;
		ipv4_ctr.count();
	}

	action dropv6() {
		meta.drop_reason = DROP_IPV6_SWITCH_ADDR_MISS;
		meta.dropped = true;
		ipv6_ctr.count();
	}

	action drop_bad_mac() {
		meta.drop_reason = DROP_MULTICAST_INVALID_MAC;
		meta.dropped = true;
	}

	action claimv4() {
		meta.is_switch_address = true;
		ipv4_ctr.count();
	}

	action claimv6() {
		meta.is_switch_address = true;
		ipv6_ctr.count();
	}


	// Table of the IPv4 addresses assigned to ports on the switch.
	table switch_ipv4_addr {
		key = {
			meta.orig_dst_ipv4 : exact;
			ig_intr_md.ingress_port : ternary;
		}
		actions = { claimv4; dropv4; }

		const size = SWITCH_IPV4_ADDRS_SIZE;
		counters = ipv4_ctr;
	}

	// Table of the IPv6 addresses assigned to ports on the switch.
	table switch_ipv6_addr {
		key = {
			hdr.ipv6.dst_addr : exact;
			ig_intr_md.ingress_port : ternary;
		}
		actions = { claimv6; dropv6; }

		const size = SWITCH_IPV6_ADDRS_SIZE;
		counters = ipv6_ctr;
	}

	apply {
		if (hdr.arp.isValid()) {
			switch_ipv4_addr.apply();
		} else if (hdr.ipv4.isValid()) {
#ifdef MULTICAST
			if (meta.is_mcast) {
				// IPv4 Multicast Address Validation (RFC 1112, RFC 7042)
				//
				// We've already validated the first 3 bytes of the MAC in the parser.
				// This cannot be checked by the parser statically.
				//
				// First, check that 4th byte of the MAC address is the lower 7
				// bits of the IPv4 address.
				bit<8> mac_byte4 = hdr.ethernet.dst_mac[23:16];
				bit<7> ipv4_lower7 = hdr.ipv4.dst_addr[22:16]; // The lower 7 bits of the first byte

				// Check 5th byte of MAC against 3rd octet of IPv4 address.
				bit<8> mac_byte5 = hdr.ethernet.dst_mac[15:8];
				bit<8> ipv4_byte3 = hdr.ipv4.dst_addr[15:8];   // Third byte

				// Check 6th byte of MAC against 4th octet of IPv4 address.
				bit<8> mac_byte6 = hdr.ethernet.dst_mac[7:0];
				bit<8> ipv4_byte4 = hdr.ipv4.dst_addr[7:0];

				// Check if MAC address follows the multicast mapping standard.
				if (mac_byte4 != (bit<8>)ipv4_lower7 ||
					mac_byte5 != ipv4_byte3 ||
					mac_byte6 != ipv4_byte4) {
					drop_bad_mac();
					drop_mcast_ctr.count(ig_intr_md.ingress_port);
					return;
				}
			} else {
				switch_ipv4_addr.apply();
			}
#else /* MULTICAST */
			switch_ipv4_addr.apply();
#endif /* MULTICAST */
		} else if (hdr.ipv6.isValid()) {
#ifdef MULTICAST
			if (meta.is_mcast) {
				// Validate the IPv6 multicast MAC address format (RFC 2464,
				// RFC 7042).
				//
				// IPv6 multicast addresses (ff00::/8) must use MAC addresses
				// that follow the format 33:33:xxxx:xxxx where the last 32 bits
				// are taken directly from the last 32 bits of the IPv6 address.
				//
				// Sadly, the first two conditions cannot be checked properly by
				// the parser, as we reach the total available parser match
				// registers on the device.
				if (hdr.ethernet.dst_mac[47:40] != 8w0x33 ||
					hdr.ethernet.dst_mac[39:32] != 8w0x33) {
						drop_bad_mac();
						drop_mcast_ctr.count(ig_intr_md.ingress_port);
						return;
				}

				// The last four conditions cannot be checked by the parser
				// statically, so we have to do this in the control stage.

				// For a 128-bit IPv6 address, we need to check the last 32 bits
				// against the last 32 bits of the MAC address.
				if (hdr.ethernet.dst_mac[31:24] != hdr.ipv6.dst_addr[31:24] ||
					hdr.ethernet.dst_mac[23:16] != hdr.ipv6.dst_addr[23:16] ||
					hdr.ethernet.dst_mac[15:8] != hdr.ipv6.dst_addr[15:8] ||
					hdr.ethernet.dst_mac[7:0] != hdr.ipv6.dst_addr[7:0]) {
						drop_bad_mac();
						drop_mcast_ctr.count(ig_intr_md.ingress_port);
						return;
				}
			}
#endif /* MULTICAST */

			if (!meta.is_mcast || meta.is_link_local_mcastv6 && !meta.encap_needed) {
				switch_ipv6_addr.apply();
			}
		}
	}
}

// This control checks for packets that require special
// handling rather than being routed normally.  These
// fall into three categories:
//    - packets that need to be handed to user space for additional processing.
//    - packets that are coming from user space and include metadata telling us
//	how to route them
//    - ipv4 ping packets destined for one of our ports, to which we can reply
//	directly
control Services(
	inout sidecar_headers_t hdr,
	inout sidecar_ingress_meta_t meta,
	in ingress_intrinsic_metadata_t ig_intr_md,
	inout ingress_intrinsic_metadata_for_tm_t ig_tm_md
) {
	Counter<bit<32>, bit<8>>(SVC_COUNTER_MAX, CounterType_t.PACKETS) service_ctr;

	// We are replying to a ping to an IP address representing one of our
	// ports.  We can't generate a new packet in the switch, but we can
	// bounce this packet back to the sender.  To accomplish that, we need
	// to swap the source and destination IP and mac addresses, change the
	// ICMP type field, and send the packet back out the port it arrived on.
	// It's not strictly necessary, but we also bump up the TTL to make sure
	// the packet makes it all the way back to the sender.
	action ping4_reply() {
		hdr.ethernet.dst_mac = meta.orig_src_mac;

		hdr.ipv4.src_addr = hdr.ipv4.dst_addr;
		hdr.ipv4.dst_addr = meta.orig_src_ipv4;
		hdr.ipv4.ttl = 255;

		hdr.icmp.type = ICMP_ECHOREPLY;
		meta.icmp_recalc = true;

		ig_tm_md.ucast_egress_port = ig_intr_md.ingress_port;

		meta.service_routed = true;
		service_ctr.count(SVC_COUNTER_V4_PING_REPLY);
	}

	action ping6_reply() {
		hdr.ethernet.dst_mac = meta.orig_src_mac;

		bit<128> orig_src = hdr.ipv6.src_addr;
		hdr.ipv6.src_addr = hdr.ipv6.dst_addr;
		hdr.ipv6.dst_addr = orig_src;
		hdr.ipv6.hop_limit = 255;

		hdr.icmp.type = ICMP6_ECHOREPLY;
		meta.icmp_recalc = true;

		ig_tm_md.ucast_egress_port = ig_intr_md.ingress_port;

		meta.service_routed = true;
		service_ctr.count(SVC_COUNTER_V6_PING_REPLY);
	}

	// Send a network service request to a service port.  Push on a
	// sidecar tag, which indicates which port the request arrived on.
	action forward_to_userspace() {
		hdr.sidecar.sc_code = SC_FWD_TO_USERSPACE;
		hdr.sidecar.sc_ingress = (bit<16>)ig_intr_md.ingress_port;
		hdr.sidecar.sc_ether_type = hdr.ethernet.ether_type;
		hdr.sidecar.setValid();
		hdr.ethernet.ether_type = ETHERTYPE_SIDECAR;
		meta.service_routed = true;
		ig_tm_md.ucast_egress_port = USER_SPACE_SERVICE_PORT;
		service_ctr.count(SVC_COUNTER_FW_TO_USER);
	}

	// Extract the intended egress port from the sidecar header, and remove
	// the header before pushing it out that port.
	action forward_from_userspace() {
		ig_tm_md.ucast_egress_port = (bit<9>)hdr.sidecar.sc_egress;
		hdr.ethernet.ether_type = hdr.sidecar.sc_ether_type;
		hdr.sidecar.setInvalid();
		meta.service_routed = true;
		service_ctr.count(SVC_COUNTER_FW_FROM_USER);
	}

	action drop_bad_ping() {
		meta.drop_reason = DROP_BAD_PING;
		meta.dropped = true;
		service_ctr.count(SVC_COUNTER_BAD_PING);
	}

	// In our implementation, there can be only two nodes on a link:
	// the switch and whatever is connected directly to it.  This
	// simple model allows us to implement link-local "multicast"
	// essentially like unicast. In particular, for these, we don't need to
	// engage the Tofino packet replication mechanism. "Inbound" multicast
	// packets always go to the service port. "Outbound" multicast
	// packets always go to the port indicated by the sidecar header.
	action mcast_inbound_link_local() {
		hdr.sidecar.sc_code = SC_FWD_TO_USERSPACE;
		hdr.sidecar.sc_ingress = (bit<16>)ig_intr_md.ingress_port;
		hdr.sidecar.sc_egress = (bit<16>)ig_tm_md.ucast_egress_port;
		hdr.sidecar.sc_ether_type = hdr.ethernet.ether_type;
		hdr.sidecar.sc_payload = 0;
		hdr.sidecar.setValid();
		hdr.ethernet.ether_type = ETHERTYPE_SIDECAR;
		meta.service_routed = true;
		ig_tm_md.ucast_egress_port = USER_SPACE_SERVICE_PORT;
		meta.is_mcast = true;
		meta.is_link_local_mcastv6 = true;
		service_ctr.count(SVC_COUNTER_INBOUND_LL);
	}

	action no_service() {
		service_ctr.count(SVC_COUNTER_PASS);
	}

	table service {
		key = {
			meta.nat_ingress_hit : exact;
			meta.is_mcast : exact;
			meta.is_link_local_mcastv6 : ternary;
			meta.is_switch_address : ternary;
			ig_intr_md.ingress_port : ternary;
			hdr.sidecar.isValid() : ternary;
			hdr.arp.isValid() : ternary;
			hdr.icmp.isValid() : ternary;
			hdr.ipv4.isValid() : ternary;
			hdr.ipv6.isValid() : ternary;
			hdr.icmp.type : ternary;
			hdr.icmp.code : ternary;
		}

		actions = {
			ping4_reply;
			ping6_reply;
			drop_bad_ping;
			forward_from_userspace;
			forward_to_userspace;
			mcast_inbound_link_local;
			no_service;
		}

		const entries = {
			( false, false, _, true, _, _, false, true, true, false, ICMP_ECHOREPLY, 0 ) : forward_to_userspace;
			( false, false, _, true, _, _, false, true, true, false, ICMP_ECHOREPLY, _ ) : drop_bad_ping;
			( false, false, _, true, _, _, false, true, true, false, ICMP_ECHO, 0 ) : ping4_reply;
			( false, false, _, true, _, _, false, true, true, false, ICMP_ECHO, _ ) : drop_bad_ping;
			( false, false, _, true, _, _, false, true, false, true, ICMP6_ECHOREPLY, 0 ) : forward_to_userspace;
			( false, false, _, true, _, _, false, true, false, true, ICMP6_ECHOREPLY, _ ) : drop_bad_ping;
			( false, false, _, true, _, _, false, true, false, true, ICMP6_ECHO, 0 ) : ping6_reply;
			( false, false, _, true, _, _, false, true, false, true, ICMP6_ECHO, _ ) : drop_bad_ping;
			( false, false, _, _, USER_SPACE_SERVICE_PORT, true, _, _, _, _, _, _ ) : forward_from_userspace;
			( false, true, true, _, USER_SPACE_SERVICE_PORT, true, _, _, _, _, _, _ ) : forward_from_userspace;
			( false, false, _, _, _, false, true, _, _, _, _, _ ) : forward_to_userspace;
			( false, false, _, true, _, _, _, _, _, _, _, _ ) : forward_to_userspace;
			// Link-local multicast
			( false, true, true, _, _, _, _, _, _, _, _, _ ) : mcast_inbound_link_local;
		}

		default_action = no_service;
		const size = 16;
	}

	apply {
		/*
		 * XXX: This can all be made simpler by doing the "is this a
		 * switch address" at the very beginning.  We can then drop non-
		 * NAT packets in the NatIngress control rather than deferring
		 * to here.  I've going with this approach as a short-term fix,
		 * as the restructuring is likely to have knock-on effects in
		 * dpd and sidecar-lite.
		 */
		if (!meta.is_switch_address && meta.nat_ingress_port && !meta.encap_needed) {
			// For packets that were not marked for NAT ingress, but which
			// arrived on an uplink port that only allows in traffic that
			// is meant to be NAT encapsulated.
			meta.drop_reason = DROP_NAT_INGRESS_MISS;
			meta.dropped = true;
		}
		else if (meta.is_switch_address && hdr.geneve.isValid() && hdr.geneve.vni != 0) {
			meta.nat_egress_hit = true;
		}
		else {
			service.apply();
		}
	}
}

control AttachedSubnetIngress (
	in sidecar_headers_t hdr,
	inout sidecar_ingress_meta_t meta
) {
	DirectCounter<bit<32>>(CounterType_t.PACKETS_AND_BYTES) attached_subnets_v4_ctr;
	DirectCounter<bit<32>>(CounterType_t.PACKETS_AND_BYTES) attached_subnets_v6_ctr;

	action forward_to_v4(ipv6_addr_t target, mac_addr_t inner_mac, geneve_vni_t vni) {
		meta.encap_needed = true;
		meta.nat_ingress_tgt = target;
		meta.nat_inner_mac = inner_mac;
		meta.nat_geneve_vni = vni;
		attached_subnets_v4_ctr.count();
	}

	table attached_subnets_v4 {
		key             = { hdr.ipv4.dst_addr: lpm; }
		actions         = { forward_to_v4 ; }

		const size      = ATTACHED_SUBNETS_V4_SIZE + 1;
		counters	= attached_subnets_v4_ctr;
	}

	action forward_to_v6(ipv6_addr_t target, mac_addr_t inner_mac, geneve_vni_t vni) {
		meta.encap_needed = true;
		meta.nat_ingress_tgt = target;
		meta.nat_inner_mac = inner_mac;
		meta.nat_geneve_vni = vni;
		attached_subnets_v6_ctr.count();
	}

	table attached_subnets_v6 {
		key             = { hdr.ipv6.dst_addr: lpm; }
		actions         = { forward_to_v6 ; }

		const size      = ATTACHED_SUBNETS_V6_SIZE + 1;
		counters	= attached_subnets_v6_ctr;
	}

	apply {
		if (hdr.ipv4.isValid()) {
			attached_subnets_v4.apply();
		} else if (hdr.ipv6.isValid()) {
			attached_subnets_v6.apply();
		}
	}
}

control NatIngress (
	inout sidecar_headers_t hdr,
	inout sidecar_ingress_meta_t meta,
	in ingress_intrinsic_metadata_t ig_intr_md
) {
	DirectCounter<bit<32>>(CounterType_t.PACKETS_AND_BYTES) ipv4_ingress_ctr;
	DirectCounter<bit<32>>(CounterType_t.PACKETS_AND_BYTES) ipv6_ingress_ctr;
	DirectCounter<bit<32>>(CounterType_t.PACKETS_AND_BYTES) nat_only_ctr;
#ifdef MULTICAST
	DirectCounter<bit<32>>(CounterType_t.PACKETS_AND_BYTES) mcast_ipv4_ingress_ctr;
	DirectCounter<bit<32>>(CounterType_t.PACKETS_AND_BYTES) mcast_ipv6_ingress_ctr;
#endif /* MULTICAST */

	action add_encap_headers(bit<16> udp_len) {
		// 8 bytes with a 4 byte option
		hdr.geneve.setValid();
		hdr.geneve.version = 0;
		hdr.geneve.opt_len = 1;
		hdr.geneve.ctrl = 0;
		hdr.geneve.crit = 0;
		hdr.geneve.reserved = 0;
		hdr.geneve.protocol = GENEVE_ENCAP_ETH;
		hdr.geneve.vni = meta.nat_geneve_vni;
		hdr.geneve.reserved2 = 0;

		// 4-byte option type 0x00 -- 'VPC-external packet'.
		hdr.geneve_opts.oxg_ext_tag.setValid();
		hdr.geneve_opts.oxg_ext_tag.class = GENEVE_OPT_CLASS_OXIDE;
		hdr.geneve_opts.oxg_ext_tag.crit = 0;
		hdr.geneve_opts.oxg_ext_tag.type = GENEVE_OPT_OXIDE_EXTERNAL;
		hdr.geneve_opts.oxg_ext_tag.reserved = 0;
		hdr.geneve_opts.oxg_ext_tag.opt_len = 0;

		// 14 bytes
		hdr.inner_eth.setValid();
		hdr.inner_eth.dst_mac = meta.nat_inner_mac;
		hdr.inner_eth.src_mac = 0;
		hdr.inner_eth.ether_type = hdr.ethernet.ether_type;

		// 8 bytes
		hdr.udp.setValid();
		hdr.udp.src_port = GENEVE_UDP_PORT;
		hdr.udp.dst_port = GENEVE_UDP_PORT;
		hdr.udp.hdr_length = udp_len;
		hdr.udp.checksum = 0;

		// 40 bytes
		hdr.ethernet.ether_type = ETHERTYPE_IPV6;
		hdr.ipv6.setValid();
		hdr.ipv6.version = 6;
		hdr.ipv6.traffic_class = 0;
		hdr.ipv6.flow_label = 0;
		hdr.ipv6.payload_len = udp_len;
		hdr.ipv6.next_hdr = IPPROTO_UDP;
		hdr.ipv6.hop_limit = 255;
		hdr.ipv6.src_addr = 0;
		hdr.ipv6.dst_addr = meta.nat_ingress_tgt;
	}

	action encap_ipv4() {
		// The forwarded payload is the inner packet plus ethernet, UDP,
		// and Geneve headers (plus external geneve TLV).
		bit<16> payload_len = hdr.ipv4.total_len + 14 + 8 + 8 + 4;

		hdr.inner_ipv4 = hdr.ipv4;
		hdr.inner_ipv4.setValid();
		hdr.ipv4.setInvalid();

		add_encap_headers(payload_len);
	}

	action encap_ipv6() {
		// The forwarded payload is the inner packet plus ethernet, UDP
		// and Geneve headers (plus external geneve TLV).  We also have
		// to add in the size of the original IPv6 header.
		bit<16> payload_len = hdr.ipv6.payload_len + 14 + 8 + 8 + 4 + 40;

		hdr.inner_ipv6 = hdr.ipv6;
		hdr.inner_ipv6.setValid();

		add_encap_headers(payload_len);
	}

	action forward_ipv4_to(ipv6_addr_t target, mac_addr_t inner_mac, geneve_vni_t vni) {
		meta.nat_ingress_hit = true;
		meta.nat_ingress_tgt = target;
		meta.nat_inner_mac = inner_mac;
		meta.nat_geneve_vni = vni;
		meta.encap_needed = true;

		ipv4_ingress_ctr.count();
	}

	table ingress_ipv4 {
		key = {
			hdr.ipv4.dst_addr : exact;
			meta.l4_dst_port : range;
		}
		actions = { forward_ipv4_to; }

		const size = IPV4_NAT_TABLE_SIZE;
		counters = ipv4_ingress_ctr;
	}

	action forward_ipv6_to(ipv6_addr_t target, mac_addr_t inner_mac, geneve_vni_t vni) {
		meta.nat_ingress_hit = true;
		meta.nat_ingress_tgt = target;
		meta.nat_inner_mac = inner_mac;
		meta.nat_geneve_vni = vni;
		meta.encap_needed = true;

		ipv6_ingress_ctr.count();
	}

	table ingress_ipv6 {
		key = {
			hdr.ipv6.dst_addr : exact;
			meta.l4_dst_port : range;
		}
		actions = { forward_ipv6_to; }

		const size = IPV6_NAT_TABLE_SIZE;
		counters = ipv6_ingress_ctr;
	}

	action nat_only_port() {
		meta.nat_ingress_port = true;
		nat_only_ctr.count();
	}

	table nat_only {
		key = { ig_intr_md.ingress_port : exact; }
		actions = { nat_only_port; }

		const size = 256;
		counters = nat_only_ctr;
	}

#ifdef MULTICAST
	action mcast_forward_ipv4_to(ipv6_addr_t target, mac_addr_t inner_mac, geneve_vni_t vni) {
		meta.nat_ingress_hit = true;
		meta.nat_ingress_tgt = target;
		meta.nat_inner_mac = inner_mac;
		meta.nat_geneve_vni = vni;
		meta.encap_needed = true;
		mcast_ipv4_ingress_ctr.count();
	}

	// Separate table for IPv4 multicast packets that need to be encapsulated.
	table ingress_ipv4_mcast {
		key = { hdr.ipv4.dst_addr : exact; }
		actions = { mcast_forward_ipv4_to; }
		const size = IPV4_MULTICAST_TABLE_SIZE;
		counters = mcast_ipv4_ingress_ctr;
	}

	action mcast_forward_ipv6_to(ipv6_addr_t target, mac_addr_t inner_mac, geneve_vni_t vni) {
		meta.nat_ingress_hit = true;
		meta.nat_ingress_tgt = target;
		meta.nat_inner_mac = inner_mac;
		meta.nat_geneve_vni = vni;
		meta.encap_needed = true;

		mcast_ipv6_ingress_ctr.count();
	}

	// Separate table for IPv6 multicast packets that need to be encapsulated.
	table ingress_ipv6_mcast {
		key = { hdr.ipv6.dst_addr : exact; }
		actions = { mcast_forward_ipv6_to; }
		const size = IPV6_MULTICAST_TABLE_SIZE;
		counters = mcast_ipv6_ingress_ctr;
	}
#endif /* MULTICAST */

	action set_icmp_dst_port() {
		meta.l4_dst_port = hdr.icmp.data[31:16];
	}

	table icmp_dst_port {
		key = {
			hdr.icmp.isValid(): ternary;
			hdr.icmp.type: ternary;
		}

		actions = {
			set_icmp_dst_port;
		}

		const entries = {
			( true, ICMP_ECHO ) : set_icmp_dst_port;
			( true, ICMP_ECHOREPLY ) : set_icmp_dst_port;
			( true, ICMP6_ECHO ) : set_icmp_dst_port;
			( true, ICMP6_ECHOREPLY ) : set_icmp_dst_port;
		}

		const size = 4;
	}

	action set_inner_tcp() {
		hdr.inner_tcp = hdr.tcp;
		hdr.inner_tcp.setValid();
		hdr.tcp.setInvalid();
	}

	action set_inner_udp() {
		hdr.inner_udp = hdr.udp;
		hdr.inner_udp.setValid();
		hdr.udp.setInvalid();
	}

	action set_inner_icmp() {
		hdr.inner_icmp = hdr.icmp;
		hdr.inner_icmp.setValid();
		hdr.icmp.setInvalid();
	}

	table ingress_hit {
		key = {
			meta.encap_needed : exact;
			hdr.tcp.isValid() : ternary;
			hdr.udp.isValid() : ternary;
			hdr.icmp.isValid() : ternary;
		}
		actions = {
			set_inner_tcp;
			set_inner_udp;
			set_inner_icmp;
			NoAction;
		}

		const entries = {
			( true, true, false, false ) : set_inner_tcp;
			( true, false, true, false  ) : set_inner_udp;
			( true, false, false, true ) : set_inner_icmp;
		}
		default_action = NoAction;
		const size = 3;
	}

	apply {
		icmp_dst_port.apply();

		// Note: This whole conditional could be simpler as a set of */
		// `const entries`, but apply (on tables) cannot be called from actions
#ifdef MULTICAST
		if (hdr.ipv4.isValid()) {
			if (meta.is_mcast) {
				ingress_ipv4_mcast.apply();
			} else if (!meta.encap_needed) {
				ingress_ipv4.apply();
			}
		} else if (hdr.ipv6.isValid()) {
			// If this is a multicast packet and not a link-local multicast,
			// we need to check the multicast table
			if (meta.is_mcast && !meta.is_link_local_mcastv6) {
				ingress_ipv6_mcast.apply();
			} else {
				ingress_ipv6.apply();
			}
		}
#else /* MULTICAST */
		if (hdr.ipv4.isValid())  {
			if (!meta.encap_needed) {
				ingress_ipv4.apply();
			}
		} else if (hdr.ipv6.isValid()) {
			ingress_ipv6.apply();
		}
#endif /* MULTICAST */

		if (ingress_hit.apply().hit) {
			if (hdr.ipv4.isValid()) {
				CalculateIPv4Len.apply(hdr, meta);
				encap_ipv4();
			} else if (hdr.ipv6.isValid()) {
				encap_ipv6();
			}

			if (hdr.vlan.isValid()) {
				// When setting up the inner headers above, we
				// copied the ether type from the outer to
				// the inner.  If this is a vlan packet, we
				// actually want the ethertype of the payload
				hdr.inner_eth.ether_type = hdr.vlan.ether_type;
				hdr.vlan.setInvalid();
			}
		} else if (!meta.is_switch_address) {
			nat_only.apply();
		}
	}
}

control NatEgress (
	inout sidecar_headers_t hdr,
	inout sidecar_ingress_meta_t meta
) {
	action drop() {
		// We only get here if the packet was marked for a nat egress,
		// but it's not a packet type allowed through nat.
		meta.drop_reason = DROP_NAT_HEADER_ERROR;
		meta.dropped = true;
	}

	action strip_outer_header() {
		hdr.inner_eth.setInvalid();
		hdr.sidecar.setInvalid();
		hdr.vlan.setInvalid();
		hdr.ipv4.setInvalid();
		hdr.ipv6.setInvalid();
		hdr.udp.setInvalid();
		hdr.tcp.setInvalid();
		hdr.geneve.setInvalid();

		// Should never be valid for outbound traffic, but no harm
		// in being careful.
		hdr.geneve_opts.oxg_ext_tag.setInvalid();
		hdr.geneve_opts.oxg_mcast_tag.setInvalid();
		hdr.geneve_opts.oxg_mcast.setInvalid();
		hdr.geneve_opts.oxg_mss_tag.setInvalid();
		hdr.geneve_opts.oxg_mss.setInvalid();
	}

	action decap_ipv4() {
		hdr.ethernet.ether_type = ETHERTYPE_IPV4;
		hdr.ipv4 = hdr.inner_ipv4;
		hdr.ipv4.setValid();
		hdr.inner_ipv4.setInvalid();
	}

	action decap_tcp() {
		hdr.tcp = hdr.inner_tcp;
		hdr.tcp.setValid();
		hdr.inner_tcp.setInvalid();
	}

	action decap_udp() {
		hdr.udp = hdr.inner_udp;
		hdr.udp.setValid();
		hdr.inner_udp.setInvalid();
	}

	action decap_ipv6() {
		hdr.ethernet.ether_type = ETHERTYPE_IPV6;
		hdr.ipv6 = hdr.inner_ipv6;
		hdr.ipv6.setValid();
		hdr.inner_ipv6.setInvalid();
	}

	action decap_icmp() {
		hdr.icmp = hdr.inner_icmp;
		hdr.icmp.setValid();
		hdr.inner_icmp.setInvalid();
	}

	action decap_ipv4_tcp() {
		strip_outer_header();
		decap_ipv4();
		decap_tcp();
	}

	action decap_ipv4_udp() {
		strip_outer_header();
		decap_ipv4();
		decap_udp();
	}

	action decap_ipv4_icmp() {
		strip_outer_header();
		decap_ipv4();
		decap_icmp();
	}

	action decap_ipv6_tcp() {
		strip_outer_header();
		decap_ipv6();
		decap_tcp();
	}

	action decap_ipv6_udp() {
		strip_outer_header();
		decap_ipv6();
		decap_udp();
	}

	action decap_ipv6_icmp() {
		strip_outer_header();
		decap_ipv6();
		decap_icmp();
	}

	table nat_egress {
		key = {
			hdr.inner_ipv4.isValid() : exact;
			hdr.inner_ipv6.isValid() : exact;
			hdr.inner_tcp.isValid() : exact;
			hdr.inner_udp.isValid() : exact;
			hdr.inner_icmp.isValid() : exact;
		}

		actions = {
			decap_ipv4_tcp;
			decap_ipv4_udp;
			decap_ipv4_icmp;
			decap_ipv6_tcp;
			decap_ipv6_udp;
			decap_ipv6_icmp;
			drop;
		}

		const entries = {
			( true, false, true, false, false ) : decap_ipv4_tcp;
			( true, false, false, true, false ) : decap_ipv4_udp;
			( true, false, false, false, true ) : decap_ipv4_icmp;
			( false, true, true, false, false ) : decap_ipv6_tcp;
			( false, true, false, true, false ) : decap_ipv6_udp;
			( false, true, false, false, true ) : decap_ipv6_icmp;
		}
		default_action = drop;

		const size = 6;
	}

	apply {
		if (meta.nat_egress_hit) {
			nat_egress.apply();
		}
	}
}

control RouterLookupIndex6(
	inout sidecar_headers_t hdr,
	inout route6_result_t res
) {
	DirectCounter<bit<32>>(CounterType_t.PACKETS_AND_BYTES) index_ctr;
	DirectCounter<bit<32>>(CounterType_t.PACKETS_AND_BYTES) forward_ctr;

	action forward_vlan(PortId_t port, ipv6_addr_t nexthop, bit<12> vlan_id) {
		hdr.vlan.setValid();

		hdr.vlan.pcp = 0;
		hdr.vlan.dei = 0;
		hdr.vlan.vlan_id = vlan_id;
		hdr.vlan.ether_type = hdr.ethernet.ether_type;
		hdr.ethernet.ether_type = ETHERTYPE_VLAN;
		res.port = port;
		res.nexthop = nexthop;
		forward_ctr.count();
	}

	action forward(PortId_t port, ipv6_addr_t nexthop) {
		res.port = port;
		res.nexthop = nexthop;
		forward_ctr.count();
	}

	/*
	 * The table size is reduced by one here just to allow the integration
	 * test to pass.  We want the lookup and forward tables to have the same
	 * capacity from dpd's perspective, and the "default" entry consumes a
	 * slot in the lookup table.
	 */
	table route {
		key             = { res.idx: exact; }
		actions         = { forward; forward_vlan; }
		const size      = IPV6_LPM_SIZE - 1;
		counters        = forward_ctr;
	}

	action unreachable() {
		res.is_hit = false;
		res.idx = 0;
		res.slots = 0;
		res.slot = 0;
		res.port = 0;
		res.nexthop = 0;
		index_ctr.count();
	}

	/*
	 * The select_route table contains 2048 pre-computed entries.
	 * It lives in another file just to keep this one manageable.
	 */
	#include <route_selector.p4>

	action index(bit<16> idx, bit<8> slots) {
		res.is_hit = true;

		res.idx = idx;
		res.slots = slots;
		res.slot = 0;

		// The rest of this data is extracted from the target table at
		// entry `res.idx`.
		res.port = 0;
		res.nexthop = 0;
		index_ctr.count();
	}

	table lookup {
		key             = { hdr.ipv6.dst_addr: lpm; }
		actions         = { index; unreachable; }
		default_action  = unreachable;
		// The table size is incremented by one here just to allow the
		// integration tests to pass, as this is used by the multicast
		// implementation as well
		const size      = IPV6_LPM_SIZE + 1;
		counters        = index_ctr;
	}

	apply {
		lookup.apply();

		if (res.is_hit) {
			/*
			 * Select which of the possible targets to use for this
			 * packet.  This is simply (flow_hash % target_count).
			 * Since the tofino p4 implementation doesn't support
			 * the mod operator, we precalculate the possible
			 * values and stick them in the select_route table.
			 */
			select_route.apply();
			res.idx = res.idx + res.slot;
			route.apply();
		}
	}
}

control RouterLookupIndex4(
	inout sidecar_headers_t hdr,
	inout route4_result_t res
) {
	DirectCounter<bit<32>>(CounterType_t.PACKETS_AND_BYTES) index_ctr;
	DirectCounter<bit<32>>(CounterType_t.PACKETS_AND_BYTES) forward_ctr;

	action forward_vlan(PortId_t port, ipv4_addr_t nexthop, bit<12> vlan_id) {
		hdr.vlan.setValid();

		hdr.vlan.pcp = 0;
		hdr.vlan.dei = 0;
		hdr.vlan.vlan_id = vlan_id;
		hdr.vlan.ether_type = hdr.ethernet.ether_type;
		hdr.ethernet.ether_type = ETHERTYPE_VLAN;
		res.port = port;
		res.nexthop = nexthop;
		res.is_v6 = false;
		forward_ctr.count();
	}

	action forward_vlan_v6(PortId_t port, ipv6_addr_t nexthop, bit<12> vlan_id) {
		hdr.vlan.setValid();

		hdr.vlan.pcp = 0;
		hdr.vlan.dei = 0;
		hdr.vlan.vlan_id = vlan_id;
		hdr.vlan.ether_type = hdr.ethernet.ether_type;
		hdr.ethernet.ether_type = ETHERTYPE_VLAN;
		res.port = port;
		res.nexthop6 = nexthop;
		res.is_v6 = true;
		forward_ctr.count();
	}

	action forward(PortId_t port, ipv4_addr_t nexthop) {
		res.port = port;
		res.nexthop = nexthop;
		res.is_v6 = false;
		forward_ctr.count();
	}

	action forward_v6(PortId_t port, ipv6_addr_t nexthop) {
		res.port = port;
		res.nexthop6 = nexthop;
		res.is_v6 = true;
		forward_ctr.count();
	}

	/*
	 * The table size is reduced by one here just to allow the integration
	 * test to pass.  We want the lookup and forward tables to have the same
	 * capacity from dpd's perspective, and the "default" entry consumes a
	 * slot in the lookup table.
	 */
	table route {
		key             = { res.idx: exact; }
		actions         = { forward; forward_v6; forward_vlan; forward_vlan_v6; }
		const size      = IPV4_LPM_SIZE - 1;
		counters        = forward_ctr;
	}

	action unreachable() {
		res.is_hit = false;
		res.idx = 0;
		res.slots = 0;
		res.slot = 0;
		res.port = 0;
		res.nexthop = 0;
		index_ctr.count();
	}

	/*
	 * The select_route table contains 2048 pre-computed entries.
	 * It lives in another file just to keep this one manageable.
	 */
	#include <route_selector.p4>

	action index(bit<16> idx, bit<8> slots) {
		res.is_hit = true;

		res.idx = idx;
		res.slots = slots;
		res.slot = 0;

		// The rest of this data is extracted from the target table at
		// entry `res.idx`.
		res.port = 0;
		res.nexthop = 0;
		index_ctr.count();
	}

	table lookup {
		key             = { hdr.ipv4.dst_addr: lpm; }
		actions         = { index; unreachable; }
		default_action  = unreachable;
		const size      = IPV4_LPM_SIZE;
		counters        = index_ctr;
	}

	apply {
		lookup.apply();

		if (res.is_hit) {
			/*
			 * Select which of the possible targets to use for this
			 * packet.  This is simply (flow_hash % target_count).
			 * Since the tofino p4 implementation doesn't support
			 * the mod operator, we precalculate the possible
			 * values and stick them in the select_route table.
			 */
			select_route.apply();
			res.idx = res.idx + res.slot;
			route.apply();
		}
	}
}

control Arp (
	inout sidecar_headers_t hdr,
	inout sidecar_ingress_meta_t meta,
	in ingress_intrinsic_metadata_t ig_intr_md,
	inout ingress_intrinsic_metadata_for_tm_t ig_tm_md
) {
	DirectCounter<bit<32>>(CounterType_t.PACKETS_AND_BYTES) ctr;

	action drop() {
		// This happens if we have explicitly added an ipv4 -> NULL_MAC
		// entry.
		meta.drop_reason = DROP_ARP_NULL;
		meta.dropped = true;
		ctr.count();
	}

	action rewrite(mac_addr_t dst_mac) {
		hdr.ethernet.dst_mac = dst_mac;
		ctr.count();
	}

	action request() {
		hdr.sidecar.sc_code = SC_ARP_NEEDED;
		hdr.sidecar.sc_ingress = (bit<16>)ig_intr_md.ingress_port;
		hdr.sidecar.sc_egress = (bit<16>)ig_tm_md.ucast_egress_port;
		hdr.sidecar.sc_ether_type = hdr.ethernet.ether_type;
		hdr.sidecar.sc_payload = (bit<128>)meta.nexthop_ipv4;
		hdr.sidecar.setValid();
		hdr.ethernet.ether_type = ETHERTYPE_SIDECAR;
		meta.service_routed = true;
		meta.drop_reason = DROP_ARP_MISS;
		// Dont set meta.dropped because we want an error packet
		// to go up to the switch.
		ig_tm_md.ucast_egress_port = USER_SPACE_SERVICE_PORT;
		ctr.count();
	}

	table tbl {
		key             = { meta.nexthop_ipv4: exact; }
		actions         = { drop; request; rewrite; }
		default_action  = request;
		const size      = IPV4_ARP_SIZE;
		counters	    = ctr;
	}

	apply { tbl.apply(); }
}

control Ndp (
	inout sidecar_headers_t hdr,
	inout sidecar_ingress_meta_t meta,
	in ingress_intrinsic_metadata_t ig_intr_md,
	inout ingress_intrinsic_metadata_for_tm_t ig_tm_md
) {
	DirectCounter<bit<32>>(CounterType_t.PACKETS_AND_BYTES) ctr;

	action drop() {
		// This happens if we have explicitly added an ipv6 -> NULL_MAC
		// entry.
		meta.drop_reason = DROP_NDP_NULL;
		meta.dropped = true;
		ctr.count();
	}

	action rewrite(mac_addr_t dst_mac)  {
		hdr.ethernet.dst_mac = dst_mac;
		ctr.count();
	}

	action request() {
		hdr.sidecar.sc_code = SC_NEIGHBOR_NEEDED;
		hdr.sidecar.sc_ingress = (bit<16>)ig_intr_md.ingress_port;
		hdr.sidecar.sc_egress = (bit<16>)ig_tm_md.ucast_egress_port;
		hdr.sidecar.sc_ether_type = hdr.ethernet.ether_type;
		hdr.sidecar.sc_payload = (bit<128>)meta.nexthop_ipv6;
		hdr.sidecar.setValid();
		hdr.ethernet.ether_type = ETHERTYPE_SIDECAR;
		meta.service_routed = true;
		meta.drop_reason = DROP_NDP_MISS;
		// Dont set meta.dropped because we want an error packet
		// to go up to the switch.
		ig_tm_md.ucast_egress_port = USER_SPACE_SERVICE_PORT;
		ctr.count();
	}

	table tbl {
		key             = { meta.nexthop_ipv6: exact; }
		actions         = { drop; rewrite; request; }
		default_action  = request;
		const size      = IPV6_NEIGHBOR_SIZE;
		counters        = ctr;
	}

	apply { tbl.apply(); }
}

control Router4 (
	inout sidecar_headers_t hdr,
	inout sidecar_ingress_meta_t meta,
	in ingress_intrinsic_metadata_t ig_intr_md,
	inout ingress_intrinsic_metadata_for_tm_t ig_tm_md
) {
	RouterLookupIndex4() lookup_idx;
	Hash<bit<8>>(HashAlgorithm_t.CRC8) index_hash;

	action icmp_error(bit<8> type, bit<8> code) {
		hdr.sidecar.sc_code = SC_ICMP_NEEDED;
		hdr.sidecar.sc_ingress = (bit<16>)ig_intr_md.ingress_port;
		hdr.sidecar.sc_egress = (bit<16>)ig_tm_md.ucast_egress_port;
		hdr.sidecar.sc_ether_type = hdr.ethernet.ether_type;
		hdr.sidecar.sc_payload = (bit<128>)type << 8 | (bit<128>)code;
		hdr.sidecar.setValid();
		hdr.ethernet.ether_type = ETHERTYPE_SIDECAR;
		meta.service_routed = true;
		ig_tm_md.ucast_egress_port = USER_SPACE_SERVICE_PORT;
	}

	apply {
		route4_result_t fwd;
		fwd.is_v6 = false;
		fwd.nexthop6 = 0;
		fwd.nexthop = 0;
		fwd.port = 0;
		fwd.is_hit = false;
		fwd.idx = 0;
		fwd.slots = 0;
		fwd.slot = 0;
		// Our route selection table is 11 bits wide, and we need 5 bits
		// of that for our "slot count" index.  Thus, we only need 6
		// bits of the 8-bit hash calculated here to complete the 11-bit
		// index.
		fwd.ecmp_hash = index_hash.get({
			hdr.ipv4.dst_addr,
			hdr.ipv4.src_addr,
			meta.l4_dst_port,
			meta.l4_src_port
		}) & 0x3f;

		lookup_idx.apply(hdr, fwd);

		if (!fwd.is_hit) {
			icmp_error(ICMP_DEST_UNREACH, ICMP_DST_UNREACH_NET);
			// Dont set meta.dropped because we want an error packet
			// to go out.
			meta.drop_reason = DROP_IPV4_UNROUTEABLE;
		} else if (hdr.ipv4.ttl == 1 && !IS_SERVICE(fwd.port)) {
			icmp_error(ICMP_TIME_EXCEEDED, ICMP_EXC_TTL);
			// Dont set meta.dropped because we want an error packet
			// to go out.
			meta.drop_reason = DROP_IPV4_TTL_EXCEEDED;
		} else {
			hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
			ig_tm_md.ucast_egress_port = fwd.port;

			meta.nexthop_ipv4 = fwd.nexthop;
			meta.nexthop_ipv6 = fwd.nexthop6;
			meta.resolve_nexthop = true;
		}
	}
}

#ifdef MULTICAST
control MulticastRouter4(
	inout sidecar_headers_t hdr,
	inout sidecar_ingress_meta_t meta,
	in ingress_intrinsic_metadata_t ig_intr_md,
	inout ingress_intrinsic_metadata_for_tm_t ig_tm_md
) {
	DirectCounter<bit<32>>(CounterType_t.PACKETS_AND_BYTES) ctr;

	action icmp_error(bit<8> type, bit<8> code) {
		hdr.sidecar.sc_code = SC_ICMP_NEEDED;
		hdr.sidecar.sc_ingress = (bit<16>)ig_intr_md.ingress_port;
		hdr.sidecar.sc_egress = (bit<16>)ig_tm_md.ucast_egress_port;
		hdr.sidecar.sc_ether_type = hdr.ethernet.ether_type;
		hdr.sidecar.sc_payload = (bit<128>)type << 8 | (bit<128>)code;
		hdr.sidecar.setValid();
		hdr.ethernet.ether_type = ETHERTYPE_SIDECAR;
		meta.service_routed = true;
		ig_tm_md.ucast_egress_port = USER_SPACE_SERVICE_PORT;
	}

	action unreachable() {
		ctr.count();
	}

	action forward_vlan(bit<12> vlan_id) {
		hdr.vlan.setValid();

		hdr.vlan.pcp = 0;
		hdr.vlan.dei = 0;
		hdr.vlan.vlan_id = vlan_id;
		hdr.vlan.ether_type = hdr.ethernet.ether_type;
		hdr.ethernet.ether_type = ETHERTYPE_VLAN;
		ctr.count();
	}

	action forward() {
		ctr.count();
	}

	table tbl {
		key = {
			hdr.ipv4.dst_addr : exact;
		}
		actions = { forward; forward_vlan; unreachable; }
		default_action = unreachable;
		const size = IPV4_MULTICAST_TABLE_SIZE;
		counters = ctr;
	}

	apply {
		// If the packet came in with a VLAN tag, we need to invalidate
		// the VLAN header before we do the lookup.  The VLAN header
		// will be re-attached if set in the forward_vlan action.
		if (hdr.vlan.isValid()) {
			hdr.ethernet.ether_type = hdr.vlan.ether_type;
			hdr.vlan.setInvalid();
		}

		if (!tbl.apply().hit) {
			icmp_error(ICMP6_DST_UNREACH, ICMP6_DST_UNREACH_NOROUTE);
			meta.drop_reason = DROP_IPV6_UNROUTEABLE;
			// Dont set meta.dropped because we want an error packet
			// to go out.
		} else if (hdr.ipv4.ttl == 1 && !meta.service_routed) {
			icmp_error(ICMP_TIME_EXCEEDED, ICMP_EXC_TTL);
			meta.drop_reason = DROP_IPV4_TTL_INVALID;
			// Dont set meta.dropped because we want an error packet
			// to go out.
		} else {
			// Set the destination port to an invalid value
			ig_tm_md.ucast_egress_port = (PortId_t)0x1ff;
			if (hdr.ipv4.isValid()) {
				hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
			}
		}
	}
}
#endif /* MULTICAST */

control Router6 (
	inout sidecar_headers_t hdr,
	inout sidecar_ingress_meta_t meta,
	in ingress_intrinsic_metadata_t ig_intr_md,
	inout ingress_intrinsic_metadata_for_tm_t ig_tm_md
) {
	RouterLookupIndex6() lookup_idx;
	Hash<bit<8>>(HashAlgorithm_t.CRC8) index_hash;

	action icmp_error(bit<8> type, bit<8> code) {
		hdr.sidecar.sc_code = SC_ICMP_NEEDED;
		hdr.sidecar.sc_ingress = (bit<16>)ig_intr_md.ingress_port;
		hdr.sidecar.sc_egress = (bit<16>)ig_tm_md.ucast_egress_port;
		hdr.sidecar.sc_ether_type = hdr.ethernet.ether_type;
		hdr.sidecar.sc_payload = (bit<128>)type << 8 | (bit<128>)code;
		hdr.sidecar.setValid();
		hdr.ethernet.ether_type = ETHERTYPE_SIDECAR;
		meta.service_routed = true;
		ig_tm_md.ucast_egress_port = USER_SPACE_SERVICE_PORT;
	}

	apply {
		route6_result_t fwd;
		fwd.nexthop = 0;
		fwd.port = 0;
		fwd.is_hit = false;
		fwd.idx = 0;
		fwd.slots = 0;
		fwd.slot = 0;
		// Our route selection table is 11 bits wide, and we need 5 bits
		// of that for our "slot count" index.  Thus, we only need 6
		// bits of the 8-bit hash calculated here to complete the 11-bit
		// index.
		fwd.ecmp_hash = index_hash.get({
			hdr.ipv6.dst_addr,
			hdr.ipv6.src_addr,
			meta.l4_dst_port,
			meta.l4_src_port
		}) & 0x3f;

		lookup_idx.apply(hdr, fwd);

		if (!fwd.is_hit) {
			icmp_error(ICMP6_DST_UNREACH, ICMP6_DST_UNREACH_NOROUTE);
			meta.drop_reason = DROP_IPV6_UNROUTEABLE;
			// Dont set meta.dropped because we want an error packet
			// to go out.
		} else if (hdr.ipv6.hop_limit == 1 && !IS_SERVICE(fwd.port)) {
			icmp_error(ICMP6_TIME_EXCEEDED, ICMP_EXC_TTL);
			meta.drop_reason = DROP_IPV6_TTL_EXCEEDED;
			// Dont set meta.dropped because we want an error packet
			// to go out.
		} else {
			ig_tm_md.ucast_egress_port = fwd.port;
			hdr.ipv6.hop_limit = hdr.ipv6.hop_limit - 1;
			meta.resolve_nexthop = true;
			meta.nexthop_ipv6 = fwd.nexthop;
		}
	}
}

#ifdef MULTICAST
control MulticastRouter6 (
	inout sidecar_headers_t hdr,
	inout sidecar_ingress_meta_t meta,
	in ingress_intrinsic_metadata_t ig_intr_md,
	inout ingress_intrinsic_metadata_for_tm_t ig_tm_md
) {
	DirectCounter<bit<32>>(CounterType_t.PACKETS_AND_BYTES) ctr;

	action icmp_error(bit<8> type, bit<8> code) {
		hdr.sidecar.sc_code = SC_ICMP_NEEDED;
		hdr.sidecar.sc_ingress = (bit<16>)ig_intr_md.ingress_port;
		hdr.sidecar.sc_egress = (bit<16>)ig_tm_md.ucast_egress_port;
		hdr.sidecar.sc_ether_type = hdr.ethernet.ether_type;
		hdr.sidecar.sc_payload = (bit<128>)type << 8 | (bit<128>)code;
		hdr.sidecar.setValid();
		hdr.ethernet.ether_type = ETHERTYPE_SIDECAR;
		meta.service_routed = true;
		ig_tm_md.ucast_egress_port = USER_SPACE_SERVICE_PORT;
	}

	action unreachable() {
		ctr.count();
	}

	action forward_vlan(bit<12> vlan_id) {
		hdr.vlan.setValid();
		hdr.vlan.pcp = 0;
		hdr.vlan.dei = 0;
		hdr.vlan.vlan_id = vlan_id;
		hdr.vlan.ether_type = hdr.ethernet.ether_type;
		hdr.ethernet.ether_type = ETHERTYPE_VLAN;
		ctr.count();
	}

	action forward() {
		ctr.count();
	}

	table tbl {
		key = {
			hdr.ipv6.dst_addr : exact;
		}
		actions = { forward; forward_vlan; unreachable; }
		default_action = unreachable;
		const size = IPV6_MULTICAST_TABLE_SIZE;
		counters = ctr;
	}

	apply {
		// If the packet came in with a VLAN tag, we need to invalidate
		// the VLAN header before we do the lookup.  The VLAN header
		// will be re-attached if set in the forward_vlan action.
		if (hdr.vlan.isValid()) {
			hdr.ethernet.ether_type = hdr.vlan.ether_type;
			hdr.vlan.setInvalid();
		}

		if (!tbl.apply().hit) {
			icmp_error(ICMP6_DST_UNREACH, ICMP6_DST_UNREACH_NOROUTE);
			meta.drop_reason = DROP_IPV6_UNROUTEABLE;
			// Dont set meta.dropped because we want an error packet
			// to go out.
		} else if (hdr.ipv6.hop_limit == 1) {
			icmp_error(ICMP6_TIME_EXCEEDED, ICMP_EXC_TTL);
			meta.drop_reason = DROP_IPV6_TTL_EXCEEDED;
			// Dont set meta.dropped because we want an error packet
			// to go out.
		} else {
			// Set the destination port to an invalid value
        	ig_tm_md.ucast_egress_port = (PortId_t)0x1ff;
			hdr.ipv6.hop_limit = hdr.ipv6.hop_limit - 1;
		}
	}
}
#endif /* MULTICAST */

control L3Router(
	inout sidecar_headers_t hdr,
	inout sidecar_ingress_meta_t meta,
	in ingress_intrinsic_metadata_t ig_intr_md,
	inout ingress_intrinsic_metadata_for_tm_t ig_tm_md
) {
	apply {
#ifdef MULTICAST
		if (hdr.ipv4.isValid()) {
			if (meta.is_mcast && !meta.is_link_local_mcastv6) {
				MulticastRouter4.apply(hdr, meta, ig_intr_md, ig_tm_md);
			} else {
				Router4.apply(hdr, meta, ig_intr_md, ig_tm_md);
			}
		} else if (hdr.ipv6.isValid()) {
			if (meta.is_mcast && !meta.is_link_local_mcastv6) {
				MulticastRouter6.apply(hdr, meta, ig_intr_md, ig_tm_md);
			} else {
				Router6.apply(hdr, meta, ig_intr_md, ig_tm_md);
			}
		}
#else /* MULTICAST */
		if (hdr.ipv4.isValid()) {
			Router4.apply(hdr, meta, ig_intr_md, ig_tm_md);
		} else if (hdr.ipv6.isValid()) {
			Router6.apply(hdr, meta, ig_intr_md, ig_tm_md);
		}
#endif /* MULTICAST */
		if (meta.resolve_nexthop) {
			if (meta.nexthop_ipv4 != 0) {
				Arp.apply(hdr, meta, ig_intr_md, ig_tm_md);
			} else {
				Ndp.apply(hdr, meta, ig_intr_md, ig_tm_md);
			}
		}
	}
}

control MacRewrite(
	inout sidecar_headers_t hdr,
	in PortId_t port
) {
	DirectCounter<bit<32>>(CounterType_t.PACKETS_AND_BYTES) ctr;

	action rewrite(mac_addr_t mac) {
		hdr.ethernet.src_mac = mac;
		ctr.count();
	}

	table mac_rewrite {
		key     = { port: exact ; }
		actions = { rewrite; }

		const size = 256;
		counters = ctr;
	}

	apply {
		mac_rewrite.apply();
	}
}

#ifdef MULTICAST
/* This control is used to rewrite the source and destination MAC addresses
 * for multicast packets. The destination MAC address is derived from the
 * destination IP address, and the source MAC address is set based on the
 * egress port the packet is being sent out on.
 */
control MulticastMacRewrite(
	inout sidecar_headers_t hdr,
	in PortId_t port
) {
	DirectCounter<bit<32>>(CounterType_t.PACKETS_AND_BYTES) ctr;

	action rewrite(mac_addr_t mac) {
		hdr.ethernet.src_mac = mac;
		ctr.count();
	}

	table mac_rewrite {
		key     = { port: exact ; }
		actions = { rewrite; }

		const size = 256;
		counters = ctr;
	}

	apply {
		if (mac_rewrite.apply().hit) {
			// Derive the destination MAC based on IP type.
			// IPV4: https://www.rfc-editor.org/rfc/rfc1112.html#section-6.4
			// IPV6: https://www.rfc-editor.org/rfc/rfc2464.html
			if (hdr.ipv4.isValid() || (!hdr.geneve.isValid() && hdr.inner_ipv4.isValid())) {
				// IPv4 multicast MAC address (01:00:5e + 23 bits of IP)
				bit<48> mcast_mac = 0;
				// Set the first three bytes to 01:00:5e (0x01005e)
				mcast_mac = (bit<48>)0x01005e << 24;

				bit<24> ip_suffix;
				// Take the last 23 bits of IPv4 address and append them
				// We mask the first byte to clear the top bit
				if (hdr.ipv4.isValid()) {
					ip_suffix = (bit<24>)(hdr.ipv4.dst_addr & 0x007fffff);
				} else {
					ip_suffix = (bit<24>)(hdr.inner_ipv4.dst_addr & 0x007fffff);
				}

				hdr.ethernet.dst_mac = mcast_mac | ((bit<48>)ip_suffix);
			} else if (hdr.ipv6.isValid() || (!hdr.geneve.isValid() && hdr.inner_ipv6.isValid())) {
				// IPv6 multicast MAC address (33:33 + last 32 bits of IPv6)
				bit<48> mcast_mac = 0;
				// Set the first two bytes to 33:33
				mcast_mac = (bit<48>)0x3333 << 32;

				bit<48> ip_suffix;
				// Take the last 32 bits of IPv6 address and append them
				if (hdr.ipv6.isValid()) {
					ip_suffix = (bit<48>)(hdr.ipv6.dst_addr[31:0]);
				} else {
					ip_suffix = (bit<48>)(hdr.inner_ipv6.dst_addr[31:0]);
				}

				hdr.ethernet.dst_mac = mcast_mac | ip_suffix;
			}
		}
	}
}

/* This control is used to configure multicast packets for replication.
 * It includes actions for dropping packets with no group, allowing
 * source-specific multicast, and configuring multicast group IDs and hashes.
 */
control MulticastIngress (
	inout sidecar_headers_t hdr,
	inout sidecar_ingress_meta_t meta,
	in ingress_intrinsic_metadata_t ig_intr_md,
	inout ingress_intrinsic_metadata_for_tm_t ig_tm_md)
{
	DirectCounter<bit<32>>(CounterType_t.PACKETS_AND_BYTES) mcast_ipv6_ctr;
	DirectCounter<bit<32>>(CounterType_t.PACKETS_AND_BYTES) mcast_ipv4_ssm_ctr;
	DirectCounter<bit<32>>(CounterType_t.PACKETS_AND_BYTES) mcast_ipv6_ssm_ctr;

	Hash<bit<13>>(HashAlgorithm_t.CRC16) mcast_hashv6_level1;
	Hash<bit<13>>(HashAlgorithm_t.CRC16) mcast_hashv6_level2;

	// Drop action for IPv4 multicast packets with no group.
	//
	// At this point, We should only allow replication for IPv6 packets that
	// are admin-scoped before possible decapping.
	action drop_mcastv4_no_group() {
		meta.drop_reason = DROP_MULTICAST_NO_GROUP;
		meta.dropped = true;
	}

	// Drop action for IPv6 multicast packets with no group.
	//
	// At this point, we should only allow replication for IPv6 packets that
	// are admin-scoped before possible decapping.
	action drop_mcastv6_no_group() {
		meta.drop_reason = DROP_MULTICAST_NO_GROUP;
		meta.dropped = true;
	}

	// Drop action for IPv6 multicast packets with no group
	// that is a valid admin-scoped multicast group.
	action drop_mcastv6_admin_scoped_no_group() {
		meta.drop_reason = DROP_MULTICAST_NO_GROUP;
		meta.dropped = true;
		mcast_ipv6_ctr.count();
	}

	// Drop action for IPv4 multicast packets with no source-specific multicast
	// group.
	action drop_mcastv4_filtered_source() {
		meta.drop_reason = DROP_MULTICAST_SOURCE_FILTERED;
		meta.dropped = true;
		mcast_ipv4_ssm_ctr.count();
	}

	// Drop action for IPv6 ulticast packets with no source-specific multicast
	// group.
	action drop_mcastv6_filtered_source() {
		meta.drop_reason = DROP_MULTICAST_SOURCE_FILTERED;
		meta.dropped = true;
		mcast_ipv6_ssm_ctr.count();
	}

	action allow_source_mcastv4() {
		// Source is allowed for source-specific multicast
		meta.allow_source_mcast = true;
		mcast_ipv4_ssm_ctr.count();
	}

	action allow_source_mcastv6() {
		// Source is allowed for source-specific multicast
		meta.allow_source_mcast = true;
		mcast_ipv6_ssm_ctr.count();
	}

	// Configure IPv6 multicast replication with bifurcated design:
	// mcast_grp_a: external/customer replication group
	// mcast_grp_b: underlay/infrastructure replication group
	action configure_mcastv6(
		MulticastGroupId_t mcast_grp_a,
		MulticastGroupId_t mcast_grp_b,
		bit<16> rid,
		bit<16> level1_excl_id,
		bit<9> level2_excl_id
	) {
		ig_tm_md.mcast_grp_a = mcast_grp_a;
		ig_tm_md.mcast_grp_b = mcast_grp_b;
		ig_tm_md.rid = rid;
		ig_tm_md.level1_exclusion_id = level1_excl_id;
		ig_tm_md.level2_exclusion_id = level2_excl_id;

		// Set multicast hash based on IPv6 packet fields
		ig_tm_md.level1_mcast_hash = (bit<13>)mcast_hashv6_level1.get({
			hdr.ipv6.src_addr,
			hdr.ipv6.dst_addr,
			hdr.ipv6.next_hdr,
			meta.l4_src_port,
			meta.l4_dst_port
		});

		// Set secondary multicast hash based on IPv6 packet fields
		ig_tm_md.level2_mcast_hash = (bit<13>)mcast_hashv6_level2.get({
			hdr.ipv6.flow_label,
			ig_intr_md.ingress_port
		});

		mcast_ipv6_ctr.count();
	}

	table mcast_source_filter_ipv4 {
		key = {
			hdr.inner_ipv4.src_addr: lpm;
			hdr.inner_ipv4.dst_addr: exact;
		}
		actions = {
			allow_source_mcastv4;
			drop_mcastv4_filtered_source;
		}
		default_action = drop_mcastv4_filtered_source;
		const size = IPV4_MULTICAST_TABLE_SIZE;
		counters = mcast_ipv4_ssm_ctr;
	}

	table mcast_replication_ipv6 {
		key = { hdr.ipv6.dst_addr: exact; }
		actions = {
			configure_mcastv6;
			drop_mcastv6_admin_scoped_no_group;
		}
		default_action = drop_mcastv6_admin_scoped_no_group;
		const size = IPV6_MULTICAST_TABLE_SIZE;
		counters = mcast_ipv6_ctr;
	}

	table mcast_source_filter_ipv6 {
		key = {
			hdr.inner_ipv6.src_addr: exact;
			hdr.inner_ipv6.dst_addr: exact;
		}
		actions = {
			allow_source_mcastv6;
			drop_mcastv6_filtered_source;
		}
		default_action = drop_mcastv6_filtered_source;
		const size = IPV6_MULTICAST_TABLE_SIZE;
		counters = mcast_ipv6_ssm_ctr;
	}

	action invalidate_external_grp() {
		invalidate(ig_tm_md.mcast_grp_a);
	}

	action invalidate_underlay_grp() {
		invalidate(ig_tm_md.mcast_grp_b);
	}

	action invalidate_grps() {
		invalidate_external_grp();
		invalidate_underlay_grp();
	}

	action invalidate_underlay_grp_and_set_decap() {
		invalidate_underlay_grp();
		meta.nat_egress_hit = true;
	}

	table mcast_tag_check {
		key = {
			ig_tm_md.mcast_grp_a : ternary;
			ig_tm_md.mcast_grp_b : ternary;
			hdr.geneve.isValid() : ternary;
			hdr.geneve_opts.oxg_mcast.isValid() : ternary;
			hdr.geneve_opts.oxg_mcast.mcast_tag : ternary;
		}
		actions = {
			invalidate_external_grp;
			invalidate_underlay_grp;
			invalidate_underlay_grp_and_set_decap;
			invalidate_grps;
			NoAction;
		}

		const entries = {
			(  _, _, true, true, MULTICAST_TAG_EXTERNAL ) : invalidate_underlay_grp_and_set_decap;
			(  _, _, true, true, MULTICAST_TAG_UNDERLAY ) : invalidate_external_grp;
			(  _, _, true, true, MULTICAST_TAG_UNDERLAY_EXTERNAL ) : NoAction;
			( 0, _, _, _, _ ) : invalidate_external_grp;
			( _, 0, _, _, _ ) : invalidate_underlay_grp;
			( 0, 0, _, _, _ ) : invalidate_grps;
		}

		const size = 6;
	}

	// Note: SSM tables currently take one extra stage in the pipeline (17->18).
	apply {
		if (hdr.geneve.isValid() && hdr.inner_ipv4.isValid()) {
			// Check if the inner destination address is an IPv4 SSM multicast
			// address.
			if (hdr.inner_ipv4.dst_addr[31:24] == 8w0xe8) {
				mcast_source_filter_ipv4.apply();
			} else {
				meta.allow_source_mcast = true;
			}
		} else if (hdr.geneve.isValid() && hdr.inner_ipv6.isValid()) {
			// Check if the inner destination address is an IPv6 SSM multicast
			// address.
			if ((hdr.inner_ipv6.dst_addr[127:120] == 8w0xff)
				&& ((hdr.inner_ipv6.dst_addr[119:116] == 4w0x3))) {
					mcast_source_filter_ipv6.apply();
			} else {
				meta.allow_source_mcast = true;
			}
		} else if (hdr.ipv4.isValid()) {
			drop_mcastv4_no_group();
		} else if (hdr.ipv6.isValid()) {
			drop_mcastv6_no_group();
		}

		if (hdr.ipv6.isValid() && meta.allow_source_mcast) {
			mcast_replication_ipv6.apply();
			mcast_tag_check.apply();
		}
	}
}


/* This control is used to configure the egress port for multicast packets.
 * It includes actions for setting the decap ports bitmap and VLAN ID
 * (if necessary), as well as stripping headers and decrementing TTL or hop
 * limit.
 */
control MulticastEgress (
	inout sidecar_headers_t hdr,
	inout sidecar_egress_meta_t meta,
	in egress_intrinsic_metadata_t eg_intr_md,
	in egress_intrinsic_metadata_for_deparser_t eg_dprsr_md
) {

	action set_decap_ports(
		bit<32> ports_0, bit<32> ports_1, bit<32> ports_2, bit<32> ports_3,
		bit<32> ports_4, bit<32> ports_5, bit<32> ports_6, bit<32> ports_7) {

		// Store the decap port configuration in metadata
		meta.decap_ports_0 = ports_0;
		meta.decap_ports_1 = ports_1;
		meta.decap_ports_2 = ports_2;
		meta.decap_ports_3 = ports_3;
		meta.decap_ports_4 = ports_4;
		meta.decap_ports_5 = ports_5;
		meta.decap_ports_6 = ports_6;
		meta.decap_ports_7 = ports_7;
    }

	action set_decap_ports_and_vlan(
		bit<32> ports_0, bit<32> ports_1, bit<32> ports_2, bit<32> ports_3,
		bit<32> ports_4, bit<32> ports_5, bit<32> ports_6, bit<32> ports_7,
		bit<12> vlan_id) {

		set_decap_ports(ports_0, ports_1, ports_2, ports_3,
			ports_4, ports_5, ports_6, ports_7);

		meta.vlan_id = vlan_id;
	}


	table mcast_tag_check {
		key = {
			hdr.ipv6.isValid(): exact;
			hdr.ipv6.dst_addr: ternary;
			hdr.geneve.isValid(): exact;
			hdr.geneve_opts.oxg_mcast.isValid(): exact;
			hdr.geneve_opts.oxg_mcast.mcast_tag: exact;
		}

		actions = { NoAction; }

		const entries = {
			// Admin-local (scope value 4): Matches IPv6 multicast addresses
			// with scope ff04::/16
			( true, IPV6_ADMIN_LOCAL_PATTERN &&& IPV6_SCOPE_MASK, true, true, 2 ) : NoAction;
			// Site-local (scope value 5): Matches IPv6 multicast addresses with
			// scope ff05::/16
			( true, IPV6_SITE_LOCAL_PATTERN &&& IPV6_SCOPE_MASK, true, true, 2 ) : NoAction;
			// Organization-local (scope value 8): Matches IPv6 multicast
			// addresses with scope ff08::/16
			( true, IPV6_ORG_SCOPE_PATTERN &&& IPV6_SCOPE_MASK, true, true, 2 ) : NoAction;
			// ULA (Unique Local Address): Matches IPv6 addresses that start
			// with fc00::/7. This is not a multicast address, but it is used
			// for other internal routing purposes.
 			( true, IPV6_ULA_PATTERN &&& IPV6_ULA_MASK, true, true, 2 ) : NoAction;
		}

		const size = 4;
	}

	table tbl_decap_ports {
		key = {
			// Matches the `external` multicast group ID.
			eg_intr_md.egress_rid: exact;
		}

		actions = {
			set_decap_ports;
			set_decap_ports_and_vlan;
		}

		// Group RIDs == Group IPs
		const size = IPV6_MULTICAST_TABLE_SIZE;
	}

	action set_port_number(bit<8> port_number) {
		meta.port_number = port_number;
	}

	table asic_id_to_port {
		key = { eg_intr_md.egress_port: exact; }

		actions = { set_port_number; }

		const size = 256;
	}

	action strip_outer_header() {
		hdr.inner_eth.setInvalid();
		hdr.ipv4.setInvalid();
		hdr.ipv6.setInvalid();
		hdr.tcp.setInvalid();
		hdr.udp.setInvalid();
		hdr.geneve.setInvalid();
		hdr.geneve_opts.oxg_ext_tag.setInvalid();
		hdr.geneve_opts.oxg_mcast_tag.setInvalid();
		hdr.geneve_opts.oxg_mcast.setInvalid();
		hdr.geneve_opts.oxg_mss_tag.setInvalid();
		hdr.geneve_opts.oxg_mss.setInvalid();
	}

	#include <port_bitmap_check.p4>

	action strip_vlan_header() {
		hdr.vlan.setInvalid();
	}

	action decrement_ttl() {
		hdr.inner_ipv4.ttl = hdr.inner_ipv4.ttl - 1;
	}

	action decrement_hop_limit() {
		hdr.inner_ipv6.hop_limit = hdr.inner_ipv6.hop_limit - 1;
	}

	action modify_ipv4() {
		strip_outer_header();
		strip_vlan_header();
		hdr.ethernet.ether_type = ETHERTYPE_IPV4;
		decrement_ttl();
	}

	action modify_ipv6() {
		strip_outer_header();
		strip_vlan_header();
		hdr.ethernet.ether_type = ETHERTYPE_IPV6;
		decrement_hop_limit();
	}

	action modify_vlan_ipv4() {
		strip_outer_header();

		hdr.vlan.setValid();

		hdr.vlan.pcp = 0;
		hdr.vlan.dei = 0;
		hdr.vlan.vlan_id = meta.vlan_id;
		hdr.vlan.ether_type = ETHERTYPE_IPV4;
		hdr.ethernet.ether_type = ETHERTYPE_VLAN;

		decrement_ttl();
	}

	action modify_vlan_ipv6() {
		strip_outer_header();

		hdr.vlan.setValid();

		hdr.vlan.pcp = 0;
		hdr.vlan.dei = 0;
		hdr.vlan.vlan_id = meta.vlan_id;
		hdr.vlan.ether_type = ETHERTYPE_IPV6;
		hdr.ethernet.ether_type = ETHERTYPE_VLAN;

		decrement_hop_limit();
	}

	table modify_hdr {
		key = {
			meta.vlan_id: ternary;
			hdr.inner_ipv4.isValid(): exact;
			hdr.inner_ipv6.isValid(): exact;
		}

		actions = {
			modify_vlan_ipv4;
			modify_vlan_ipv6;
			modify_ipv4;
			modify_ipv6;
		}

		const entries = {
			(0, true, false) : modify_ipv4();
			(0, false, true) : modify_ipv6();
			(_, true, false) : modify_vlan_ipv4();
			(_, false, true) : modify_vlan_ipv6();
		}

		const size = 4;
	}

	apply {
		if (mcast_tag_check.apply().hit) {
			if (tbl_decap_ports.apply().hit) {
				if (asic_id_to_port.apply().hit) {
					port_bitmap_check.apply();
				}
				if (meta.bitmap_result != 0) {
					meta.ipv4_checksum_recalc = true;
					modify_hdr.apply();
				}
			}
		}
	}
}
#endif /* MULTICAST */

control Ingress(
	inout sidecar_headers_t hdr,
	inout sidecar_ingress_meta_t meta,
	in ingress_intrinsic_metadata_t ig_intr_md,
	in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
	inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
	inout ingress_intrinsic_metadata_for_tm_t ig_tm_md)
{
	Filter() filter;
	AttachedSubnetIngress() attached_subnet_ingress;
	Services() services;
	NatIngress() nat_ingress;
	NatEgress() nat_egress;
	L3Router() l3_router;
#ifdef MULTICAST
	MulticastIngress() mcast_ingress;
#endif /* MULTICAST */
	MacRewrite() mac_rewrite;

	Counter<bit<64>, PortId_t>(512, CounterType_t.PACKETS_AND_BYTES) ingress_ctr;
	Counter<bit<64>, PortId_t>(512, CounterType_t.PACKETS_AND_BYTES) egress_ctr;
	Counter<bit<32>, PortId_t>(512, CounterType_t.PACKETS) drop_port_ctr;
	Counter<bit<32>, bit<8>>(DROP_REASON_MAX, CounterType_t.PACKETS) drop_reason_ctr;
	Counter<bit<32>, bit<10>>(1024, CounterType_t.PACKETS) packet_ctr;

	apply {
		ingress_ctr.count(ig_intr_md.ingress_port);
		packet_ctr.count(meta.pkt_type);

		if (meta.ipv4_checksum_err) {
			meta.drop_reason = DROP_IPV4_CHECKSUM_ERR;
			meta.dropped = true;
		} else if (!meta.dropped) {
			// Always apply the filter first, as it may drop packets
			// that are not valid for the rest of the pipeline or tag metadata
			// accordingly.
			filter.apply(hdr, meta, ig_intr_md);
		}

		if (!meta.is_mcast || meta.is_link_local_mcastv6) {
			attached_subnet_ingress.apply(hdr, meta);
		}

		// We perform NAT ingress before multicast replication to ensure
		// that the NAT'd outer address is used for multicast
		// replication to inbound groups
		if (!meta.dropped && !hdr.geneve.isValid()) {
			nat_ingress.apply(hdr, meta, ig_intr_md);
		}

		if (!meta.dropped) {
			if (!meta.is_mcast || meta.is_link_local_mcastv6) {
				services.apply(hdr, meta, ig_intr_md, ig_tm_md);
#ifdef MULTICAST
			} else if (meta.is_mcast && !meta.is_link_local_mcastv6) {
				mcast_ingress.apply(hdr, meta, ig_intr_md, ig_tm_md);
#endif /* MULTICAST */
			}
		}

		if (!meta.dropped && !meta.service_routed) {
			if (hdr.geneve.isValid()) {
				nat_egress.apply(hdr, meta);
			}
			if (!meta.dropped) {
				l3_router.apply(hdr, meta, ig_intr_md, ig_tm_md);
			}
		}

		if (meta.dropped) {
			// Handle dropped packets
			ig_dprsr_md.drop_ctl = 1;
			drop_port_ctr.count(ig_intr_md.ingress_port);
			drop_reason_ctr.count(meta.drop_reason);
		} else if (!meta.is_mcast) {
			egress_ctr.count(ig_tm_md.ucast_egress_port);
			if (ig_tm_md.ucast_egress_port != USER_SPACE_SERVICE_PORT) {
				mac_rewrite.apply(hdr, ig_tm_md.ucast_egress_port);
			}
			meta.bridge_hdr.setInvalid();
			ig_tm_md.bypass_egress = 1w1;
		}

		if (meta.encap_needed) {
			// This works around a few things which cropped up in
			// supporting several concurrent Geneve options:
			//
			// - Why aren't we just accessing
			//   `hdr.geneve_opts.oxg_ext_tag`?
			//   > error: bytes within W2 appear multiple times in
			//     checksum 1
			//   And so on, for various other checksums. I assume
			//   this is because there are theoretically several
			//   parser paths which could set this header. However,
			//   we know on this code path that the header could only
			//   have been pushed and was never *in* the initial
			//   parse (nat_ingress).
			//
			// - Why are we storing this in metadata?
			//   > error: Non-zero constant entry in checksum
			//     calculation not implemented yet: 16w0x129
			//   Fairly straightforward, and I imagine this could
			//   be the easier one to fix in tofino-p4c. This
			//   `todo!()` covers various other tricks, including
			//   wrapping the const in a struct/header.
			//
			// This value is derived from the geneve option pushed in
			// NatIngress:
			//
			//              class = GENEVE_OPT_CLASS_OXIDE
			//                           vvvvvvvvvv
			//                           0x01, 0x29
			//                           0x00, 0x00
			//                             ^^    ^^
			// id = GENEVE_OPT_OXIDE_EXTERNAL    reserved, len = 0
			meta.nat_ingress_csum = 16w0x0129;
		}
	}
}

control IngressDeparser(packet_out pkt,
	inout sidecar_headers_t hdr,
	in sidecar_ingress_meta_t meta,
	in ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md
) {
	Checksum() icmp_checksum;
	Checksum() nat_checksum;
	Checksum() ipv4_checksum;

	apply {
		// The following code would be more naturally (and, one
		// imagines, more efficiently) represented by a collection of
		// nested 'if' statements.  However, as of SDE 9.7.0, Intel's
		// compiler can not recognize that those nested 'if's are
		// mutually exclusive, and thus each is assigned its own
		// checksum engine, exceeding the hardware's limit.  Rewriting
		// the logic as seen below somehow makes the independence
		// apparent to the compiler.
		if (meta.encap_needed && hdr.inner_ipv4.isValid() &&
		    hdr.inner_udp.isValid()) {
			hdr.udp.checksum = nat_checksum.update({
				COMMON_FIELDS, IPV4_FIELDS, hdr.inner_udp});
		}
		if (meta.encap_needed && hdr.inner_ipv4.isValid() &&
		    hdr.inner_tcp.isValid()) {
			hdr.udp.checksum = nat_checksum.update({
				COMMON_FIELDS, IPV4_FIELDS, hdr.inner_tcp});
		}
		/* COMPILER BUG: I cannot convince the tofino to compute this correctly.
		 * Conveniently, we don't actually need it, see RFC 6935.
		 *
		 *     if (meta.encap_needed && hdr.inner_ipv4.isValid() &&
		 *         hdr.inner_icmp.isValid()) {
		 *         hdr.udp.checksum = nat_checksum.update({
		 *             COMMON_FIELDS, IPV4_FIELDS, hdr.inner_icmp});
		 *     }
		 *
		 */
		if (meta.encap_needed && hdr.inner_ipv6.isValid() &&
		    hdr.inner_udp.isValid()) {
			hdr.udp.checksum = nat_checksum.update({
				COMMON_FIELDS, IPV6_FIELDS, hdr.inner_udp});
		}
		if (meta.encap_needed && hdr.inner_ipv6.isValid() &&
		    hdr.inner_tcp.isValid()) {
			hdr.udp.checksum = nat_checksum.update({
				COMMON_FIELDS, IPV6_FIELDS, hdr.inner_tcp});
		}
		/* COMPILER BUG: I cannot convince the tofino to compute this correctly.
		 * Conveniently, we don't actually need it, see RFC 6935.
		 *
		 *     if (meta.nat_ingress_hit && hdr.inner_ipv6.isValid() &&
		 *         hdr.inner_icmp.isValid()) {
		 *         hdr.udp.checksum = nat_checksum.update({
		 *		       COMMON_FIELDS, IPV6_FIELDS, hdr.inner_icmp});
		 *     }
		 *
		 */

		if (hdr.ipv4.isValid()) {
			hdr.ipv4.hdr_checksum = ipv4_checksum.update({
				hdr.ipv4.version, hdr.ipv4.ihl, hdr.ipv4.diffserv,
				hdr.ipv4.total_len,
				hdr.ipv4.identification,
				hdr.ipv4.flags, hdr.ipv4.frag_offset,
				hdr.ipv4.ttl, hdr.ipv4.protocol,
				hdr.ipv4.src_addr,
				hdr.ipv4.dst_addr
			});
		}

		if (hdr.icmp.isValid() && meta.icmp_recalc) {
			hdr.icmp.hdr_checksum = icmp_checksum.update({
				hdr.icmp.type, hdr.icmp.code, meta.icmp_csum
			});
		}

		pkt.emit(meta.bridge_hdr);
		pkt.emit(hdr);
	}
}

control Egress(
	inout sidecar_headers_t hdr,
	inout sidecar_egress_meta_t meta,
	in egress_intrinsic_metadata_t eg_intr_md,
	in egress_intrinsic_metadata_from_parser_t eg_prsr_md,
	inout egress_intrinsic_metadata_for_deparser_t eg_dprsr_md,
	inout egress_intrinsic_metadata_for_output_port_t eg_oport_md
) {
#ifdef MULTICAST
	MulticastMacRewrite() mac_rewrite;
	MulticastEgress() mcast_egress;

	Counter<bit<64>, PortId_t>(512, CounterType_t.PACKETS_AND_BYTES) unicast_ctr;
	Counter<bit<64>, PortId_t>(512, CounterType_t.PACKETS_AND_BYTES) mcast_ctr;
	Counter<bit<64>, PortId_t>(512, CounterType_t.PACKETS_AND_BYTES) link_local_mcast_ctr;
	Counter<bit<64>, PortId_t>(512, CounterType_t.PACKETS_AND_BYTES) external_mcast_ctr;
	Counter<bit<64>, PortId_t>(512, CounterType_t.PACKETS_AND_BYTES) underlay_mcast_ctr;
	Counter<bit<32>, PortId_t>(512, CounterType_t.PACKETS) drop_port_ctr;
	Counter<bit<32>, bit<8>>(DROP_REASON_MAX, CounterType_t.PACKETS) drop_reason_ctr;

	apply {
		// Check multicast egress packets by checking that RID is not 0.
		bool is_egress_rid_mcast = eg_intr_md.egress_rid > 0;
		// We track IPv6 multicast packets separately for counters.
		bool is_link_local_ipv6_mcast = false;
		if (hdr.ipv6.isValid()) {
			bit<16> ipv6_prefix = (bit<16>)hdr.ipv6.dst_addr[127:112];
			is_link_local_ipv6_mcast = (ipv6_prefix == 16w0xff02);
		}
		bool is_mcast = is_egress_rid_mcast || is_link_local_ipv6_mcast;

		if (is_egress_rid_mcast == true) {
			if (meta.bridge_hdr.ingress_port == eg_intr_md.egress_port) {
				// If the ingress port is the same as the egress port, drop
				// the packet
				meta.drop_reason = DROP_MULTICAST_PATH_FILTERED;
				eg_dprsr_md.drop_ctl = 1;
			} else {
				mcast_egress.apply(hdr, meta, eg_intr_md, eg_dprsr_md);
				mac_rewrite.apply(hdr, eg_intr_md.egress_port);
			}
		} else if (eg_intr_md.egress_rid == 0 &&
		    eg_intr_md.egress_rid_first == 1) {
			// Drop CPU copies (RID=0) to prevent unwanted packets on port 0
			eg_dprsr_md.drop_ctl = 1;
			meta.drop_reason = DROP_MULTICAST_CPU_COPY;
		}

		if (meta.drop_reason != 0) {
			// Handle dropped packets
			drop_port_ctr.count(eg_intr_md.egress_port);
			drop_reason_ctr.count(meta.drop_reason);
		} else if (is_mcast == true) {
			mcast_ctr.count(eg_intr_md.egress_port);

			if (is_link_local_ipv6_mcast) {
				link_local_mcast_ctr.count(eg_intr_md.egress_port);
			} else if (hdr.geneve.isValid()) {
				external_mcast_ctr.count(eg_intr_md.egress_port);
			} else if (hdr.geneve.isValid() &&
			           hdr.geneve_opts.oxg_mcast.isValid() &&
			           hdr.geneve_opts.oxg_mcast.mcast_tag == MULTICAST_TAG_UNDERLAY) {
				underlay_mcast_ctr.count(eg_intr_md.egress_port);
			}
		} else {
			// non-multicast packets should bypass the egress
			// pipeline, so we would expect this to be 0.
			unicast_ctr.count(eg_intr_md.egress_port);
		}
	}
#else /* MULTICAST */
	apply { }
#endif /* MULTICAST */
}

control EgressDeparser(
	packet_out pkt,
	inout sidecar_headers_t hdr,
	in sidecar_egress_meta_t meta,
	in egress_intrinsic_metadata_for_deparser_t eg_dprsr_md
) {
#ifdef MULTICAST
	Checksum() ipv4_checksum;

	apply {
		// We only need to recalculate the checksum if the packet is
		// modified in the case of replication to both external and
		// underlay multicast ports, as the TTL and hop limit
		// are decremented if packets headed toward external multicast
		// subscribers are decapped/stripped.
		if (meta.ipv4_checksum_recalc && hdr.inner_ipv4.isValid()) {
			hdr.inner_ipv4.hdr_checksum = ipv4_checksum.update({
				hdr.inner_ipv4.version, hdr.inner_ipv4.ihl, hdr.inner_ipv4.diffserv,
				hdr.inner_ipv4.total_len,
				hdr.inner_ipv4.identification,
				hdr.inner_ipv4.flags, hdr.inner_ipv4.frag_offset,
				hdr.inner_ipv4.ttl, hdr.inner_ipv4.protocol,
				hdr.inner_ipv4.src_addr,
				hdr.inner_ipv4.dst_addr
			});
		}
		pkt.emit(hdr);
	}
#else
	apply { pkt.emit(hdr); }
#endif
}

Pipeline(
	IngressParser(),
	Ingress(),
	IngressDeparser(),
	EgressParser(),
	Egress(),
	EgressDeparser()
) pipe;

Switch(pipe) main;
