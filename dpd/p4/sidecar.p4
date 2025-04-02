#if __TARGET_TOFINO__ == 2
#include <t2na.p4>
const bit<9> USER_SPACE_SERVICE_PORT = 0;
#else
#include <tna.p4>
const bit<9> USER_SPACE_SERVICE_PORT = 192;
#endif

#include <headers.p4>
#include <constants.p4>
#include <parser.p4>

// Top-level function to validate IPv4 multicast MAC addresses.
//
// Validate the IPv4 multicast MAC address format (RFC 1112, RFC 7042).
// IPv4 multicast addresses (224.0.0.0/4 or 0xE0000000/4) must
// use MAC addresses that follow the IANA-assigned OUI format
// 01:00:5e + 0 as first bit of the second byte,
// followed by 23 bits derived from the IPv4 address.
bool validate_ipv4_mcast_mac(
    in mac_addr_t mac_addr,
    in ipv4_addr_t ipv4_addr
) {
	// First byte should be 0x01
	bit<8> mac_validate1 = mac_addr[47:40];
	// Second byte should be 0x00
	bit<8> mac_validate2 = mac_addr[39:32];
	// Third byte should be 0x5e
	bit<8> mac_validate3 = mac_addr[31:24];
	// Fourth byte should match IP[23:16] & 0x7f
	bit<8> mac_validate4 = mac_addr[23:16];
	// Extract just the lower 7 bits from the second octet
	bit<7> ipv4_lower7 = ipv4_addr[22:16];

	// This validation covers the most critical part of the
	// multicast MAC format, restricting to the range
	// 01-00-5E-00-00-00 through 01-00-5E-7F-FF-FF, which are the
	// 2^23 addresses assigned for IPv4 multicast as specified in
	// RFC 7042.
	//
	// We are limited to 4 conditional checks, so we can't check
	// the full 23 bits of the IPv4 address.
	return (mac_validate1 == 8w0x01 &&
			mac_validate2 == 8w0x00 &&
			mac_validate3 == 8w0x5e &&
			mac_validate4 == (bit<8>)ipv4_lower7);
}

// Top-level function to validate IPv6 multicast MAC addresses.
//
// Validate the IPv6 multicast MAC address format (RFC 2464, RFC 7042).
// IPv6 multicast addresses (ff00::/8) must use MAC addresses
// that follow the format 33:33:xxxx:xxxx where the last 32 bits
// are taken directly from the last 32 bits of the IPv6 address.
bool validate_ipv6_mcast_mac(
    in mac_addr_t mac_addr,
    in ipv6_addr_t ipv6_addr
) {
    // First byte should be 0x33
    bit<8> mac_validate1 = mac_addr[47:40];
    // Second byte should be 0x33
    bit<8> mac_validate2 = mac_addr[39:32];
    // Third byte should match IPv6[31:24]
    bit<8> mac_validate3 = mac_addr[31:24];
    // Fourth byte should match IPv6[23:16]
    bit<8> mac_validate4 = mac_addr[23:16];

    // Extract the last 32 bits of IPv6 address for comparison
    bit<8> ipv6_byte4 = ipv6_addr[31:24];
    bit<8> ipv6_byte5 = ipv6_addr[23:16];

    // The IPv6 multicast MAC address uses the fixed prefix 33:33
    // followed by the last 32 bits of the IPv6 address. This
    // mapping is defined in RFC 2464 section 7 and confirmed in
    // RFC 7042 section 2.3.1.
    return (mac_validate1 == 8w0x33 &&
            mac_validate2 == 8w0x33 &&
            mac_validate3 == ipv6_byte4 &&
            mac_validate4 == ipv6_byte5);
}

control Filter(
	inout sidecar_headers_t hdr,
	inout sidecar_ingress_meta_t meta,
	inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
	in ingress_intrinsic_metadata_t ig_intr_md
) {
	DirectCounter<bit<32>>(CounterType_t.PACKETS_AND_BYTES) ipv4_ctr;
	DirectCounter<bit<32>>(CounterType_t.PACKETS_AND_BYTES) ipv6_ctr;
	Counter<bit<32>, PortId_t>(512, CounterType_t.PACKETS) drop_mcast_ctr;
	Counter<bit<32>, bit<8>>(DROP_REASON_MAX, CounterType_t.PACKETS) drop_reason_ctr;
	bit<16> mcast_scope;

	action dropv4() {
		ig_dprsr_md.drop_ctl = 1;
		meta.drop_reason = DROP_IPV4_SWITCH_ADDR_MISS;
		ipv4_ctr.count();
	}

	action dropv6() {
		ig_dprsr_md.drop_ctl = 1;
		meta.drop_reason = DROP_IPV6_SWITCH_ADDR_MISS;
		ipv6_ctr.count();
	}

	action claimv4() {
		meta.is_switch_address = true;
		ipv4_ctr.count();
	}

	action claimv6() {
		meta.is_switch_address = true;
		ipv6_ctr.count();
	}

	action drop_mcast_local_interface() {
		ig_dprsr_md.drop_ctl = 1;
		meta.drop_reason = DROP_MULTICAST_TO_LOCAL_INTERFACE;
	}

	action drop_invalid_mcast_mac() {
		ig_dprsr_md.drop_ctl = 1;
		meta.drop_reason = DROP_MULTICAST_INVALID_MAC;
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
		// Initialize the multicast metadata fields to false before we
		// start processing the packet for the filter.
		// meta.is_mcast = false;
		// meta.is_link_local_mcast = false;

		if (hdr.arp.isValid()) {
			switch_ipv4_addr.apply();
		} else if (hdr.ipv4.isValid()) {
			// Check if this is an IPv4 multicast address
			bit<16> mcast_scope_v4 = (bit<16>)hdr.ipv4.dst_addr[31:28];
			if (mcast_scope_v4 == 16w0xe) {
				bool is_valid = validate_ipv4_mcast_mac(hdr.ethernet.dst_mac,
														hdr.ipv4.dst_addr);
				if (is_valid) {
					meta.is_mcast = true;
				} else {
					drop_invalid_mcast_mac();
					drop_mcast_ctr.count(ig_intr_md.ingress_port);
					drop_reason_ctr.count(meta.drop_reason);
				}
			}
			switch_ipv4_addr.apply();
		} else if (hdr.ipv6.isValid()) {
			bit<16> mcast_scope_v6 = (bit<16>)hdr.ipv6.dst_addr[127:112];
			if (mcast_scope_v6 == 16w0xff01) {
				// Interface-local multicast
				drop_mcast_local_interface();
				drop_mcast_ctr.count(ig_intr_md.ingress_port);
				drop_reason_ctr.count(meta.drop_reason);
			} else if (hdr.ipv6.dst_addr[127:120] == 8w0xff) {
				bool is_valid = validate_ipv6_mcast_mac(hdr.ethernet.dst_mac,
														hdr.ipv6.dst_addr);
				if (is_valid) {
					if (mcast_scope_v6 == 16w0xff02) {
						// Link-local multicast
						meta.is_link_local_mcast = true;
					}
					meta.is_mcast = true;
				} else {
					drop_invalid_mcast_mac();
					drop_mcast_ctr.count(ig_intr_md.ingress_port);
					drop_reason_ctr.count(meta.drop_reason);
				}
			}
			switch_ipv6_addr.apply();
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
	inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
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
		service_ctr.count(SVC_COUNTER_V4_PING_REPLY);
		hdr.ethernet.dst_mac = meta.orig_src_mac;

		hdr.ipv4.src_addr = hdr.ipv4.dst_addr;
		hdr.ipv4.dst_addr = meta.orig_src_ipv4;
		hdr.ipv4.ttl = 255;

		hdr.icmp.type = ICMP_ECHOREPLY;
		meta.icmp_recalc = true;

		ig_tm_md.ucast_egress_port = ig_intr_md.ingress_port;

		meta.service_routed = true;
	}

	action ping6_reply() {
		service_ctr.count(SVC_COUNTER_V6_PING_REPLY);
		hdr.ethernet.dst_mac = meta.orig_src_mac;

		bit<128> orig_src = hdr.ipv6.src_addr;
		hdr.ipv6.src_addr = hdr.ipv6.dst_addr;
		hdr.ipv6.dst_addr = orig_src;
		hdr.ipv6.hop_limit = 255;

		hdr.icmp.type = ICMP6_ECHOREPLY;
		meta.icmp_recalc = true;

		ig_tm_md.ucast_egress_port = ig_intr_md.ingress_port;

		meta.service_routed = true;
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
		ig_dprsr_md.drop_ctl = 1;
		meta.drop_reason = DROP_BAD_PING;
		service_ctr.count(SVC_COUNTER_BAD_PING);
	}

	// In our implementation, there can be only two nodes on a link:
	// the switch and whatever is connected directly to it.  This
	// simple model allows us to implement link-local "multicast"
	// essentially like unicast.  In particular, for these, we don't need to */
	// engage the Tofino packet replication mechanism.  "Inbound" multicast
	// packets always go to the service port.  "Outbound" multicast
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
		meta.is_link_local_mcast = true;
	}

	table service {
		key = {
			ig_dprsr_md.drop_ctl: exact;
			meta.nat_ingress_hit: exact;
			meta.is_mcast: exact;
			meta.is_link_local_mcast: ternary;
			meta.is_switch_address: ternary;
			ig_intr_md.ingress_port: ternary;
			hdr.sidecar.isValid(): ternary;
			hdr.arp.isValid(): ternary;
			hdr.icmp.isValid(): ternary;
			hdr.ipv4.isValid(): ternary;
			hdr.ipv6.isValid(): ternary;
			hdr.icmp.type: ternary;
			hdr.icmp.code: ternary;
		}

		actions = {
			ping4_reply;
			ping6_reply;
			drop_bad_ping;
			forward_from_userspace;
			forward_to_userspace;
			mcast_inbound_link_local;
			NoAction;
		}

		const entries = {
			( 0, false, false, _, true, _, _, false, true, true, false, ICMP_ECHOREPLY, 0 ) : forward_to_userspace;
			( 0, false, false, _, true, _, _, false, true, true, false, ICMP_ECHOREPLY, _ ) : drop_bad_ping;
			( 0, false, false, _, true, _, _, false, true, true, false, ICMP_ECHO, 0 ) : ping4_reply;
			( 0, false, false, _, true, _, _, false, true, true, false, ICMP_ECHO, _ ) : drop_bad_ping;
			( 0, false, false, _, true, _, _, false, true, false, true, ICMP6_ECHOREPLY, 0 ) : forward_to_userspace;
			( 0, false, false, _, true, _, _, false, true, false, true, ICMP6_ECHOREPLY, _ ) : drop_bad_ping;
			( 0, false, false, _, true, _, _, false, true, false, true, ICMP6_ECHO, 0 ) : ping6_reply;
			( 0, false, false, _, true, _, _, false, true, false, true, ICMP6_ECHO, _ ) : drop_bad_ping;
			( 0, false, false, _, _, USER_SPACE_SERVICE_PORT, true, _, _, _, _, _, _ ) : forward_from_userspace;
			( 0, false, true, true, _, USER_SPACE_SERVICE_PORT, true, _, _, _, _, _, _ ) : forward_from_userspace;
			( 0, false, false, _, _, _, false, true, _, _, _, _, _ ) : forward_to_userspace;
			( 0, false, false, _, true, _, _, _, _, _, _, _, _ ) : forward_to_userspace;
			// Link-local multicast
			( 0, false, true, true, _, _, _, _, _, _, _, _, _ ) : mcast_inbound_link_local;
		}

		default_action = NoAction;
		const size = 13;
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
		if (!meta.is_switch_address && meta.nat_ingress_port && !meta.nat_ingress_hit) {
			// For packets that were not marked for NAT ingress, but which
			// arrived on an uplink port that only allows in traffic that
			// is meant to be NAT encapsulated.
			meta.drop_reason = DROP_NAT_INGRESS_MISS;
			ig_dprsr_md.drop_ctl = 1;
		}
		else if (meta.is_switch_address && hdr.geneve.isValid() && hdr.geneve.vni != 0) {
			meta.nat_egress_hit = true;
		}
		else {
			service.apply();
		}
	}
}

control NatIngress (
	inout sidecar_headers_t hdr,
	inout sidecar_ingress_meta_t meta,
	in ingress_intrinsic_metadata_t ig_intr_md
) {
	DirectCounter<bit<32>>(CounterType_t.PACKETS_AND_BYTES) ipv4_ingress_counter;
	DirectCounter<bit<32>>(CounterType_t.PACKETS_AND_BYTES) ipv6_ingress_counter;
	DirectCounter<bit<32>>(CounterType_t.PACKETS_AND_BYTES) nat_only_counter;

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

		// 4-byte option -- 'VPC-external packet'.
		hdr.geneve_opts.ox_external_tag.setValid();
		hdr.geneve_opts.ox_external_tag.class = GENEVE_OPT_CLASS_OXIDE;
		hdr.geneve_opts.ox_external_tag.crit = 0;
		hdr.geneve_opts.ox_external_tag.type = GENEVE_OPT_OXIDE_EXTERNAL;
		hdr.geneve_opts.ox_external_tag.reserved = 0;
		hdr.geneve_opts.ox_external_tag.opt_len = 0;

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

	/* Encapsulate the inner packet in a Geneve header for IPv4/IPv6 packets.
	 *
	 * This is a separate file for reusability.
	 */
	#include <encap.p4>

	action forward_ipv4_to(ipv6_addr_t target, mac_addr_t inner_mac,
	    geneve_vni_t vni) {
		meta.nat_ingress_hit = true;
		meta.nat_ingress_tgt = target;
		meta.nat_inner_mac = inner_mac;
		meta.nat_geneve_vni = vni;
		ipv4_ingress_counter.count();
	}

	table ingress_ipv4 {
		key = {
			hdr.ipv4.dst_addr : exact;
			meta.l4_dst_port : range;
		}
		actions = { forward_ipv4_to; }

		const size = IPV4_NAT_TABLE_SIZE;
		counters = ipv4_ingress_counter;
	}


	action forward_ipv6_to(ipv6_addr_t target, mac_addr_t inner_mac,
	    geneve_vni_t vni) {
		meta.nat_ingress_hit = true;
		meta.nat_ingress_tgt = target;
		meta.nat_inner_mac = inner_mac;
		meta.nat_geneve_vni = vni;
		ipv6_ingress_counter.count();
	}

	table ingress_ipv6 {
		key = {
			hdr.ipv6.dst_addr : exact;
			meta.l4_dst_port : range;
		}
		actions = { forward_ipv6_to; }

		const size = IPV6_NAT_TABLE_SIZE;
		counters = ipv6_ingress_counter;
	}

	/* Invert the source and destination addresses.
	 *
	 * This is a separate file for reusability.
	 */
	#include <ipv4_set_len.p4>

	action nat_only_port() {
		meta.nat_ingress_port = true;
		nat_only_counter.count();
	}

	table nat_only {
		key = {
			ig_intr_md.ingress_port : exact;
		}
		actions = { nat_only_port; }

		const size = 256;
		counters = nat_only_counter;
	}

	apply {
		// TODO ideally we would do this during parsing, but the Intel compiler
		// throws a fit.
		if (hdr.icmp.isValid()) {
			if( hdr.icmp.type == ICMP_ECHO || hdr.icmp.type == ICMP_ECHOREPLY ||
				hdr.icmp.type == ICMP6_ECHO || hdr.icmp.type == ICMP6_ECHOREPLY
			) {
				meta.l4_dst_port = hdr.icmp.data[31:16];
			}
		}

		if (hdr.ipv4.isValid()) {
			ingress_ipv4.apply();
		} else if (hdr.ipv6.isValid()) {
			ingress_ipv6.apply();
		}

		if (meta.nat_ingress_hit) {
			if (hdr.tcp.isValid()) {
				hdr.inner_tcp = hdr.tcp;
				hdr.inner_tcp.setValid();
				hdr.tcp.setInvalid();
			} else if (hdr.udp.isValid()) {
				hdr.inner_udp = hdr.udp;
				hdr.inner_udp.setValid();
				hdr.udp.setInvalid();
			} else if (hdr.icmp.isValid()) {
				hdr.inner_icmp = hdr.icmp;
				hdr.inner_icmp.setValid();
				hdr.icmp.setInvalid();
			}

			if (hdr.ipv4.isValid()) {
				ipv4_set_len.apply();
				invert();
				encap_ipv4();
			} else if (hdr.ipv6.isValid()) {
				encap_ipv6();
			}
			if (hdr.vlan.isValid()) {
				// When setting up the inner headers above, we
				// copied the ether type from the outer to
				// the inner.  If this is a vlan packet, we
				// actually want the ethertype of the payload.
				hdr.inner_eth.ether_type = hdr.vlan.ether_type;
				hdr.vlan.setInvalid();
			}
		} else if (!meta.is_switch_address) {
			nat_only.apply();
		}
	}
}

control NatIngressMulticast (
	inout sidecar_headers_t hdr,
	inout sidecar_egress_meta_t meta,
	in egress_intrinsic_metadata_t eg_intr_md
) {
	DirectCounter<bit<32>>(CounterType_t.PACKETS_AND_BYTES) counter;

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

		// 4-byte option -- 'VPC-external packet'.
		hdr.geneve_opts.ox_external_tag.setValid();
		hdr.geneve_opts.ox_external_tag.class = GENEVE_OPT_CLASS_OXIDE;
		hdr.geneve_opts.ox_external_tag.crit = 0;
		hdr.geneve_opts.ox_external_tag.type = GENEVE_OPT_OXIDE_EXTERNAL;
		hdr.geneve_opts.ox_external_tag.reserved = 0;
		hdr.geneve_opts.ox_external_tag.opt_len = 0;

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
		// The multicast target is the NAT target for multicast packets. */
		// TODO: Should this change in the future?
		hdr.ipv6.dst_addr = MULTICAST_NAT_TARGET;
	}

	/* Encapsulate the inner packet in a Geneve header for IPv4/IPv6 packets.
	 *
	 * This is a separate file for reusability.
	 */
	#include <encap.p4>

	action forward_to(mac_addr_t inner_mac, geneve_vni_t vni) {
		meta.nat_ingress_hit = true;
		meta.nat_inner_mac = inner_mac;
		meta.nat_geneve_vni = vni;
		counter.count();
	}

	table tbl {
		key = {
			meta.mcast_group : exact;
			eg_intr_md.egress_rid : exact;
		}
		actions = { forward_to; }

		const size = MULTICAST_NAT_TABLE_SIZE;
		counters = counter;
	}

	apply {
		tbl.apply();

		if (meta.nat_ingress_hit) {
			if (hdr.tcp.isValid()) {
				hdr.inner_tcp = hdr.tcp;
				hdr.inner_tcp.setValid();
				hdr.tcp.setInvalid();
			} else if (hdr.udp.isValid()) {
				hdr.inner_udp = hdr.udp;
				hdr.inner_udp.setValid();
				hdr.udp.setInvalid();
			} else if (hdr.icmp.isValid()) {
				hdr.inner_icmp = hdr.icmp;
				hdr.inner_icmp.setValid();
				hdr.icmp.setInvalid();
			}
			if (hdr.ipv4.isValid()) {
				encap_ipv4();
			} else if (hdr.ipv6.isValid()) {
				encap_ipv6();
			}

			if (hdr.vlan.isValid()) {
				// When setting up the inner headers above, we
				// copied the ether type from the outer to
				// the inner.  If this is a vlan packet, we
				// actually want the ethertype of the payload.
				hdr.inner_eth.ether_type = hdr.vlan.ether_type;
				hdr.vlan.setInvalid();
			}
		}
	}
}


control NatEgress (
	inout sidecar_headers_t hdr,
	inout sidecar_ingress_meta_t meta,
	inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md
) {
	action drop() {
		ig_dprsr_md.drop_ctl = 1;
		// We only get here if the packet was marked for a nat egress,
		// but it's not a packet type allowed through nat.
		meta.drop_reason = DROP_NAT_HEADER_ERROR;
	}

   /*
	* Decapsulate the packet from a Geneve header.
	*
	* This is a separate file for reusability.
	*/
	#include <decap.p4>

	apply {
		if (meta.nat_egress_hit) {
			nat_egress.apply();
		}
	}
}

control NatEgressMulticast (
	inout sidecar_headers_t hdr,
	inout sidecar_egress_meta_t meta,
	inout egress_intrinsic_metadata_for_deparser_t eg_dprsr_md
) {
	action drop() {
		eg_dprsr_md.drop_ctl = 1;
		// We only get here if the packet was marked for a nat egress,
		// but it's not a packet type allowed through nat.
		meta.drop_reason = DROP_NAT_HEADER_ERROR;
	}

   /*
	* Decapsulate the packet from a Geneve header for IPv4/IPv6 packets.
	*
	* This is a separate file for reusability.
	*/
	#include <decap.p4>

	apply {
		nat_egress.apply();
	}
}


struct route6_result_t {
	ipv6_addr_t nexthop;
	PortId_t port;
	bool is_hit;
}

control RouterLookup6(
	inout sidecar_headers_t hdr,
	out   route6_result_t res
) {
	DirectCounter<bit<32>>(CounterType_t.PACKETS_AND_BYTES) counter;

	action unreachable() {
		res.port = 0;
		res.nexthop = 0;
		res.is_hit = false;
		counter.count();
	}

	action forward_vlan(PortId_t port, ipv6_addr_t nexthop, bit<12> vlan_id) {
		hdr.vlan.setValid();

		hdr.vlan.pcp = 0;
		hdr.vlan.dei = 0;
		hdr.vlan.vlan_id = vlan_id;
		hdr.vlan.ether_type = hdr.ethernet.ether_type;
		hdr.vlan.setValid();
		hdr.ethernet.ether_type = ETHERTYPE_VLAN;
		res.port = port;
		res.nexthop = nexthop;
		res.is_hit = true;
		counter.count();
	}

	action forward(PortId_t port, ipv6_addr_t nexthop) {
		res.port = port;
		res.nexthop = nexthop;
		res.is_hit = true;
		counter.count();
	}

	table tbl {
		key             = { hdr.ipv6.dst_addr: lpm; }
		actions         = { forward; forward_vlan; unreachable; }
		default_action  = unreachable;
		// The table size is incremented by one here just to allow the
		// integration tests to pass, as this is used by the multicast
		// implementation as well
		const size      = IPV6_LPM_SIZE + 1;
		counters        = counter;
	}

	apply { tbl.apply(); }
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

control RouterLookupIndex4(
	inout sidecar_headers_t hdr,
	inout route4_result_t res
) {
	DirectCounter<bit<32>>(CounterType_t.PACKETS_AND_BYTES) index_counter;
	DirectCounter<bit<32>>(CounterType_t.PACKETS_AND_BYTES) forward_counter;

	action forward_vlan(PortId_t port, ipv4_addr_t nexthop, bit<12> vlan_id) {
		hdr.vlan.setValid();

		hdr.vlan.pcp = 0;
		hdr.vlan.dei = 0;
		hdr.vlan.vlan_id = vlan_id;
		hdr.vlan.ether_type = hdr.ethernet.ether_type;
		hdr.vlan.setValid();
		hdr.ethernet.ether_type = ETHERTYPE_VLAN;
		res.port = port;
		res.nexthop = nexthop;
		forward_counter.count();
	}

	action forward(PortId_t port, ipv4_addr_t nexthop) {
		res.port = port;
		res.nexthop = nexthop;
		forward_counter.count();
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
		const size      = IPV4_LPM_SIZE - 1;
		counters        = forward_counter;
	}

	action unreachable() {
		res.is_hit = false;
		res.idx = 0;
		res.slots = 0;
		res.slot = 0;
		res.port = 0;
		res.nexthop = 0;
		index_counter.count();
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
		index_counter.count();
	}

	table lookup {
		key             = { hdr.ipv4.dst_addr: lpm; }
		actions         = { index; unreachable; }
		default_action  = unreachable;
		const size      = IPV4_LPM_SIZE;
		counters        = index_counter;
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
	inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
	in ingress_intrinsic_metadata_t ig_intr_md,
	inout ingress_intrinsic_metadata_for_tm_t ig_tm_md
) {
	DirectCounter<bit<32>>(CounterType_t.PACKETS_AND_BYTES) counter;

	action drop() {
		ig_dprsr_md.drop_ctl = 1;
		// This happens if we have explicitly added an ipv4 -> NULL_MAC
		// entry.
		meta.drop_reason = DROP_ARP_NULL;
		counter.count();
	}

	action rewrite(mac_addr_t dst_mac) {
		hdr.ethernet.dst_mac = dst_mac;
		counter.count();
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
		ig_tm_md.ucast_egress_port = USER_SPACE_SERVICE_PORT;
		counter.count();
	}

	table tbl {
		key             = { meta.nexthop_ipv4: exact; }
		actions         = { drop; request; rewrite; }
		default_action  = request;
		const size      = IPV4_ARP_SIZE;
		counters	= counter;
	}

	apply { tbl.apply(); }
}

control Ndp (
	inout sidecar_headers_t hdr,
	inout sidecar_ingress_meta_t meta,
	inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
	in ingress_intrinsic_metadata_t ig_intr_md,
	inout ingress_intrinsic_metadata_for_tm_t ig_tm_md
) {
	DirectCounter<bit<32>>(CounterType_t.PACKETS_AND_BYTES) counter;

	action drop() {
		ig_dprsr_md.drop_ctl = 1;
		// This happens if we have explicitly added an ipv6 -> NULL_MAC
		// entry.
		meta.drop_reason = DROP_NDP_NULL;
		counter.count();
	}

	action rewrite(mac_addr_t dst_mac)  {
		hdr.ethernet.dst_mac = dst_mac;
		counter.count();
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
		ig_tm_md.ucast_egress_port = USER_SPACE_SERVICE_PORT;
		counter.count();
	}

	table tbl {
		key             = { meta.nexthop_ipv6: exact; }
		actions         = { drop; rewrite; request; }
		default_action  = request;
		const size      = IPV6_NEIGHBOR_SIZE;
		counters	= counter;
	}

	apply { tbl.apply(); }
}

control Router4 (
	inout sidecar_headers_t hdr,
	inout sidecar_ingress_meta_t meta,
	inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
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
		if (meta.ipv4_checksum_err) {
			ig_dprsr_md.drop_ctl = 1;
			meta.drop_reason = DROP_IPV4_CHECKSUM_ERR;
			return;
		} else if (hdr.ipv4.ttl == 0) {
			ig_dprsr_md.drop_ctl = 1;
			meta.drop_reason = DROP_IPV4_TTL_INVALID;
			return;
		}

		route4_result_t fwd;
		fwd.nexthop = 0;
		fwd.port = 0;
		fwd.is_hit = false;
		fwd.idx = 0;
		fwd.slots = 0;
		fwd.slot = 0;
		fwd.hash = index_hash.get({
			hdr.ipv4.dst_addr,
			hdr.ipv4.src_addr,
			meta.l4_dst_port,
			meta.l4_src_port
		});
		meta.bridge_md.flow_hash = fwd.hash;

		lookup_idx.apply(hdr, fwd);

		if (!fwd.is_hit) {
			icmp_error(ICMP_DEST_UNREACH, ICMP_DST_UNREACH_NET);
			meta.drop_reason = DROP_IPV4_UNROUTEABLE;
		} else if (hdr.ipv4.ttl == 1 && !IS_SERVICE(fwd.port)) {
			icmp_error(ICMP_TIME_EXCEEDED, ICMP_EXC_TTL);
			meta.drop_reason = DROP_IPV4_TTL_EXCEEDED;
		} else {
			hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
			ig_tm_md.ucast_egress_port = fwd.port;

			meta.nexthop_ipv4 = fwd.nexthop;
			Arp.apply(hdr, meta, ig_dprsr_md, ig_intr_md, ig_tm_md);
		}
	}
}

control MulticastRouter4(
	inout sidecar_headers_t hdr,
	inout sidecar_egress_meta_t meta,
	inout egress_intrinsic_metadata_for_deparser_t eg_dprsr_md,
	in egress_intrinsic_metadata_t eg_intr_md
) {

	RouterLookupIndex4() lookup_idx;

	apply {
		if (hdr.ipv4.ttl <= 1) {
			eg_dprsr_md.drop_ctl = 1;
			meta.drop_reason = DROP_IPV4_TTL_INVALID;
			return;
		}

		route4_result_t fwd;
		fwd.nexthop = 0;
		fwd.port = 0;
		fwd.is_hit = false;
		fwd.idx = 0;
		fwd.slots = 0;
		fwd.slot = 0;
		fwd.hash = meta.flow_hash;

		lookup_idx.apply(hdr, fwd);

		if (!fwd.is_hit) {
			meta.drop_reason = DROP_IPV4_UNROUTEABLE;
		} else {
			hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
		}
	}
}

control Router6 (
	inout sidecar_headers_t hdr,
	inout sidecar_ingress_meta_t meta,
	inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
	in ingress_intrinsic_metadata_t ig_intr_md,
	inout ingress_intrinsic_metadata_for_tm_t ig_tm_md
) {
	RouterLookup6() lookup;

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
		if (hdr.ipv6.hop_limit == 0) {
			ig_dprsr_md.drop_ctl = 1;
			meta.drop_reason = DROP_IPV6_TTL_INVALID;
			return;
		}

		route6_result_t fwd;
		fwd.nexthop = 0;
		lookup.apply(hdr, fwd);

		if (!fwd.is_hit) {
			icmp_error(ICMP6_DST_UNREACH, ICMP6_DST_UNREACH_NOROUTE);
			meta.drop_reason = DROP_IPV6_UNROUTEABLE;
		} else if (hdr.ipv6.hop_limit == 1 && !IS_SERVICE(fwd.port)) {
			icmp_error(ICMP6_TIME_EXCEEDED, ICMP_EXC_TTL);
			meta.drop_reason = DROP_IPV6_TTL_EXCEEDED;
		} else {
			ig_tm_md.ucast_egress_port = fwd.port;
			hdr.ipv6.hop_limit = hdr.ipv6.hop_limit - 1;
			meta.nexthop_ipv6 = fwd.nexthop;
			Ndp.apply(hdr, meta, ig_dprsr_md, ig_intr_md, ig_tm_md);
		}
	}
}

control MulticastRouter6 (
	inout sidecar_headers_t hdr,
	inout sidecar_egress_meta_t meta,
	inout egress_intrinsic_metadata_for_deparser_t eg_dprsr_md
) {
	RouterLookup6() lookup;

	apply {
		// Multicast traffic absolutely should not be routed with hop_limit=1,
		// as that's link-local.
		if (hdr.ipv6.hop_limit <= 1) {
			eg_dprsr_md.drop_ctl = 1;
			meta.drop_reason = DROP_IPV6_TTL_INVALID;
			return;
		}

		route6_result_t fwd;
		fwd.nexthop = 0;
		lookup.apply(hdr, fwd);

		if (!fwd.is_hit) {
			meta.drop_reason = DROP_IPV6_UNROUTEABLE;
		} else {
			hdr.ipv6.hop_limit = hdr.ipv6.hop_limit - 1;
		}
	}
}

control L3Router(
	inout sidecar_headers_t hdr,
	inout sidecar_ingress_meta_t meta,
	inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
	in ingress_intrinsic_metadata_t ig_intr_md,
	inout ingress_intrinsic_metadata_for_tm_t ig_tm_md
) {
	apply {
		if (hdr.ipv4.isValid()) {
			Router4.apply(hdr, meta, ig_dprsr_md, ig_intr_md, ig_tm_md);
		} else if (hdr.ipv6.isValid()) {
			Router6.apply(hdr, meta, ig_dprsr_md, ig_intr_md, ig_tm_md);
		}
	}
}

control L3RouterMulticast(
	inout sidecar_headers_t hdr,
	inout sidecar_egress_meta_t meta,
	inout egress_intrinsic_metadata_for_deparser_t eg_dprsr_md,
	in egress_intrinsic_metadata_t eg_intr_md
) {
	apply {
		if (hdr.ipv4.isValid()) {
			MulticastRouter4.apply(hdr, meta, eg_dprsr_md, eg_intr_md);
		} else if (hdr.ipv6.isValid()) {
			MulticastRouter6.apply(hdr, meta, eg_dprsr_md);
		}
	}
}

control MacRewrite(
	inout sidecar_headers_t hdr,
	in PortId_t port)
{
	action rewrite(mac_addr_t mac) {
		hdr.ethernet.src_mac = mac;
	}

	table mac_rewrite {
		key     = { port: exact ; }
		actions = { rewrite; NoAction; }

		default_action = NoAction;
		const size = 256;
	}

	apply {
		mac_rewrite.apply();
	}
}

// This control is responsible for routing and replication multipcast packets.
control MulticastIngress (
	inout sidecar_headers_t hdr,
	inout sidecar_ingress_meta_t meta,
	inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
	in ingress_intrinsic_metadata_t ig_intr_md,
	inout ingress_intrinsic_metadata_for_tm_t ig_tm_md)
{
	DirectCounter<bit<32>>(CounterType_t.PACKETS_AND_BYTES) mcast_ipv4_ctr;
	DirectCounter<bit<32>>(CounterType_t.PACKETS_AND_BYTES) mcast_ipv6_ctr;
	Hash<bit<13>>(HashAlgorithm_t.CRC16) mcast_hashv4_level1;
	Hash<bit<13>>(HashAlgorithm_t.CRC16) mcast_hashv4_level2;
	Hash<bit<13>>(HashAlgorithm_t.CRC16) mcast_hashv6_level1;
	Hash<bit<13>>(HashAlgorithm_t.CRC16) mcast_hashv6_level2;

	// Action to handle when no multicast group is found
	action drop_mcastv4_no_group() {
		ig_dprsr_md.drop_ctl = 1;
		meta.drop_reason = DROP_MULTICAST_NO_GROUP;
		mcast_ipv4_ctr.count();
	}

		// Action to handle when no multicast group is found
	action drop_mcastv6_no_group() {
		ig_dprsr_md.drop_ctl = 1;
		meta.drop_reason = DROP_MULTICAST_NO_GROUP;
		mcast_ipv6_ctr.count();
	}

	// Action for handling IPv4 multicast
	action configure_mcastv4(
		MulticastGroupId_t mcast_grp,
		bit<16> level1_excl_id,
		bit<9> level2_excl_id
	) {
		ig_tm_md.mcast_grp_a = mcast_grp;

		// Set replication ID to multicast group ID
		ig_tm_md.rid = mcast_grp;
		meta.bridge_md.mcast_group = mcast_grp;

		// Set multicast hash based on packet fields
		ig_tm_md.level1_mcast_hash = (bit<13>)mcast_hashv4_level1.get({
        	hdr.ipv4.src_addr,
        	hdr.ipv4.dst_addr,
        	hdr.ipv4.protocol,
        	meta.l4_src_port,
        	meta.l4_dst_port
    	});

		// Set secondary multicast hash based on packet fields
		ig_tm_md.level2_mcast_hash = (bit<13>)mcast_hashv4_level2.get({
        	(bit<16>)hdr.ipv4.identification,
        	ig_intr_md.ingress_port
    	});

		// Set exclusion IDs
		ig_tm_md.level1_exclusion_id = level1_excl_id;
		ig_tm_md.level2_exclusion_id = level2_excl_id;

		mcast_ipv4_ctr.count();
	}

	// Action for handling IPv6 multicast
	action configure_mcastv6(
		MulticastGroupId_t mcast_grp,
		bit<16> level1_excl_id,
		bit<9> level2_excl_id
	) {
		ig_tm_md.mcast_grp_a = mcast_grp;

		// Set replication ID to multicast group ID
		ig_tm_md.rid = mcast_grp;
		meta.bridge_md.mcast_group = mcast_grp;

		// Set multicast hash based on packet fields
		ig_tm_md.level1_mcast_hash = (bit<13>)mcast_hashv6_level1.get({
        	hdr.ipv6.src_addr,
        	hdr.ipv6.dst_addr,
        	hdr.ipv6.next_hdr,
        	meta.l4_src_port,
        	meta.l4_dst_port
    	});

		// Set secondary multicast hash based on packet fields
		ig_tm_md.level2_mcast_hash = (bit<13>)mcast_hashv6_level2.get({
        	hdr.ipv6.flow_label,
        	ig_intr_md.ingress_port
    	});

		// Set exclusion IDs
		ig_tm_md.level1_exclusion_id = level1_excl_id;
		ig_tm_md.level2_exclusion_id = level2_excl_id;

		mcast_ipv6_ctr.count();
	}

	// Table for looking up multicast group information
	table mcast_route_ipv4 {
		key               = { hdr.ipv4.dst_addr: exact; }
		actions           = { configure_mcastv4; drop_mcastv4_no_group; }
		default_action    = drop_mcastv4_no_group;
		const size        = MULTICAST_TABLE_SIZE;
		counters          = mcast_ipv4_ctr;
	}

	table mcast_route_ipv6 {
		key               = { hdr.ipv6.dst_addr: exact; }
		actions           = { configure_mcastv6; drop_mcastv6_no_group; }
		default_action    = drop_mcastv6_no_group;
		const size        = MULTICAST_TABLE_SIZE;
		counters          = mcast_ipv6_ctr;
	}

	apply {
		if (hdr.ipv4.isValid()) {
			mcast_route_ipv4.apply();

		} else if (hdr.ipv6.isValid()) {
			// Multicast traffic absolutely should not be routed with TTL=1, as
			// that's link-local.
			if (hdr.ipv6.hop_limit <= 1) {
				ig_dprsr_md.drop_ctl = 1;
				meta.drop_reason = DROP_IPV6_TTL_EXCEEDED;
			} else {
				mcast_route_ipv6.apply();
			}
		}
	}
}

control Ingress(
	inout sidecar_headers_t hdr,
	inout sidecar_ingress_meta_t meta,
	in ingress_intrinsic_metadata_t ig_intr_md,
	in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
	inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
	inout ingress_intrinsic_metadata_for_tm_t ig_tm_md)
{
	Filter() filter;
	Services() services;
	NatIngress() nat_ingress;
	NatEgress() nat_egress;
	L3Router() l3_router;
	MulticastIngress() multicast_ingress;

	Counter<bit<64>, PortId_t>(512, CounterType_t.PACKETS_AND_BYTES) ingress_ctr;
	Counter<bit<32>, PortId_t>(512, CounterType_t.PACKETS) drop_port_ctr;
	Counter<bit<32>, bit<8>>(DROP_REASON_MAX, CounterType_t.PACKETS) drop_reason_ctr;
	Counter<bit<32>, bit<10>>(1024, CounterType_t.PACKETS) packet_ctr;

	action set_bridge_meta() {
	    meta.bridge_md.setValid();

		meta.bridge_md.nat_ingress_hit = (bit<1>)meta.nat_ingress_hit;
		meta.bridge_md.body_checksum = meta.body_checksum;
		meta.bridge_md.icmp_recalc = (bit<1>)meta.icmp_recalc;
		meta.bridge_md.icmp_csum = meta.icmp_csum;
		meta.bridge_md.l4_length = meta.l4_length;
	}

	apply {
		ingress_ctr.count(ig_intr_md.ingress_port);
		packet_ctr.count(meta.pkt_type);

		filter.apply(hdr, meta, ig_dprsr_md, ig_intr_md);

		if (meta.is_mcast && !meta.is_link_local_mcast) {
			multicast_ingress.apply(hdr, meta, ig_dprsr_md, ig_intr_md, ig_tm_md);
		}

		if (!meta.is_mcast || meta.is_link_local_mcast) {
			nat_ingress.apply(hdr, meta, ig_intr_md);
			services.apply(hdr, meta, ig_dprsr_md, ig_intr_md, ig_tm_md);

			if (!meta.service_routed && ig_dprsr_md.drop_ctl == 0) {
				nat_egress.apply(hdr, meta, ig_dprsr_md);
				l3_router.apply(hdr, meta, ig_dprsr_md, ig_intr_md, ig_tm_md);
			}
		}

		if (meta.drop_reason != 0) {
			// Handle dropped packets
			drop_port_ctr.count(ig_intr_md.ingress_port);
			drop_reason_ctr.count(meta.drop_reason);
		}

		// Always set the bridge metadata
		set_bridge_meta();
	}
}

control IngressDeparser(packet_out pkt,
	inout sidecar_headers_t hdr,
	in sidecar_ingress_meta_t meta,
	in ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md
) {
	apply {
		pkt.emit(meta.bridge_md);
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

	NatIngressMulticast() nat_ingress;
	NatEgressMulticast() nat_egress;
	L3RouterMulticast() l3_router;
	MacRewrite() mac_rewrite;

	Counter<bit<64>, PortId_t>(512, CounterType_t.PACKETS_AND_BYTES) egress_ctr;
	Counter<bit<64>, PortId_t>(512, CounterType_t.PACKETS_AND_BYTES) ucast_ctr;
	Counter<bit<64>, PortId_t>(512, CounterType_t.PACKETS_AND_BYTES) mcast_ctr;
	Counter<bit<32>, PortId_t>(512, CounterType_t.PACKETS) drop_port_ctr;
	Counter<bit<32>, bit<8>>(DROP_REASON_MAX, CounterType_t.PACKETS) drop_reason_ctr;

	action encode_ipv4_mcast_fields() {
		hdr.ipv4.identification = eg_intr_md.egress_rid;
	}

	action encode_ipv6_mcast_fields() {
		hdr.ipv6.flow_label = (bit<20>)eg_intr_md.egress_rid;
	}

	// Define a match-action table for encoding multicast fields into the packet
	table encode_mcast_fields {
		key = {
			hdr.ipv4.isValid(): exact;
			hdr.ipv6.isValid(): exact;
		}

		actions = {
			encode_ipv4_mcast_fields;
			encode_ipv6_mcast_fields;
		}

		const entries = {
			(true, false) : encode_ipv4_mcast_fields();
			(false, true) : encode_ipv6_mcast_fields();
		}

		size = 2;
	}

	apply {
		// Check multicast egress packets by enforcing replication_id usage
		if (eg_intr_md.egress_rid > 0) {
			mcast_ctr.count(eg_intr_md.egress_port);
			encode_mcast_fields.apply();
			nat_ingress.apply(hdr, meta, eg_intr_md);

			if (eg_dprsr_md.drop_ctl == 0) {
				nat_egress.apply(hdr, meta, eg_dprsr_md);
				l3_router.apply(hdr, meta, eg_dprsr_md, eg_intr_md);
			}
        } else if (eg_intr_md.egress_rid == 0 &&
				   eg_intr_md.egress_rid_first == 1) {
			// Drop CPU copies (RID=0) to prevent unwanted packets on port 0
			eg_dprsr_md.drop_ctl = 1;
			meta.drop_reason = DROP_MULTICAST_CPU_COPY;
		} else {
			ucast_ctr.count(eg_intr_md.egress_port);
		}

		if (meta.drop_reason != 0) {
			// Handle dropped packets
			drop_port_ctr.count(eg_intr_md.egress_port);
			drop_reason_ctr.count(meta.drop_reason);
		} else {
			if (eg_intr_md.egress_port != USER_SPACE_SERVICE_PORT) {
				if (!hdr.ipv6.isValid() ||
					(hdr.ipv6.isValid() && (bit<16>)hdr.ipv6.dst_addr[127:112] != 16w0xff02)) {
					mac_rewrite.apply(hdr, eg_intr_md.egress_port);
				}
			}
			egress_ctr.count(eg_intr_md.egress_port);
		}
	}
}

control EgressDeparser(packet_out pkt,
	inout sidecar_headers_t hdr,
	in sidecar_egress_meta_t meta,
	in egress_intrinsic_metadata_for_deparser_t eg_dprsr_md
) {

	Checksum() ipv4_checksum;
	Checksum() icmp_checksum;
	Checksum() nat_checksum;

	apply {
		// The following code would be more naturally (and, one
		// imagines, more efficiently) represented by a collection of
		// nested 'if' statements.  However, as of SDE 9.7.0, Intel's
		// compiler can not recognize that those nested 'if's are
		// mutually exclusive, and thus each is assigned its own
		// checksum engine, exceeding the hardware's limit.  Rewriting
		// the logic as seen below somehow makes the independence
		// apparent to the compiler.

		if (meta.nat_ingress_hit && hdr.inner_ipv4.isValid() &&
		    hdr.inner_udp.isValid()) {
			hdr.udp.checksum = nat_checksum.update({
				COMMON_FIELDS, IPV4_FIELDS, hdr.inner_udp});
		}

		if (meta.nat_ingress_hit && hdr.inner_ipv4.isValid() &&
		    hdr.inner_tcp.isValid()) {
			hdr.udp.checksum = nat_checksum.update({
				COMMON_FIELDS, IPV4_FIELDS, hdr.inner_tcp});
		}

		/* COMPILER BUG: I cannot convince the tofino to compute this correctly.
		 * Conveniently, we dont actually need it, see RFC 6935.
		 *
		 *     if (meta.nat_ingress_hit && hdr.inner_ipv4.isValid() &&
		 *         hdr.inner_icmp.isValid()) {
		 *         hdr.udp.checksum = nat_checksum.update({
		 *             COMMON_FIELDS, IPV4_FIELDS, hdr.inner_icmp});
		 *     }
		 *
		 */

		if (meta.nat_ingress_hit && hdr.inner_ipv6.isValid() &&
		    hdr.inner_udp.isValid()) {
			hdr.udp.checksum = nat_checksum.update({
				COMMON_FIELDS, IPV6_FIELDS, hdr.inner_udp});
		}

		if (meta.nat_ingress_hit && hdr.inner_ipv6.isValid() &&
		    hdr.inner_tcp.isValid()) {
			hdr.udp.checksum = nat_checksum.update({
				COMMON_FIELDS, IPV6_FIELDS, hdr.inner_tcp});
		}

		/* COMPILER BUG: I cannot convince the tofino to compute this correctly.
		 * Conveniently, we dont actually need it, see RFC 6935.
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

		pkt.emit(hdr);
	}
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
