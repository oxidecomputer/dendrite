// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

parser IngressParser(
	packet_in pkt,
	out sidecar_headers_t hdr,
	out sidecar_ingress_meta_t meta,
	out ingress_intrinsic_metadata_t ig_intr_md
) {
	Checksum() ipv4_checksum;
	Checksum() icmp_checksum;
	Checksum() nat_checksum;

	ParserCounter() geneve_chunks;

	/* tofino-required state */
	state start {
		pkt.extract(ig_intr_md);
		transition meta_init;
	}

	state meta_init {
		meta.dropped = false;
		meta.ipv4_checksum_err = false;
		meta.is_switch_address = false;
		meta.is_mcast = false;
		meta.allow_source_mcast = false;
		meta.is_link_local_mcastv6 = false;
		meta.service_routed = false;
		meta.nat_egress_hit = false;
		meta.nat_ingress_hit = false;
		meta.nat_ingress_port = false;
		meta.nat_ingress_tgt = 0;
		meta.nat_inner_mac = 0;
		meta.nat_geneve_vni = 0;
		meta.icmp_recalc = false;
		meta.icmp_csum = 0;
		meta.l4_src_port = 0;
		meta.l4_dst_port = 0;
		meta.l4_length = 0;
		meta.body_checksum = 0;
		meta.nexthop_ipv4 = 0;
		meta.nexthop_ipv6 = 0;
		meta.orig_src_mac = 0;
		meta.orig_src_ipv4 = 0;
		meta.orig_dst_ipv4 = 0;
		meta.pkt_type = 0;
		meta.drop_reason = 0;
		meta.nat_ingress_csum = 0;

		meta.bridge_hdr.setValid();
		meta.bridge_hdr.ingress_port = ig_intr_md.ingress_port;

		transition port_metadata;
	}

	state port_metadata {
		pkt.advance(PORT_METADATA_SIZE);
		transition parse_ethernet;
	}

	state parse_ethernet {
		pkt.extract(hdr.ethernet);

		meta.pkt_type = meta.pkt_type | PKT_ETHER;
		meta.orig_src_mac = hdr.ethernet.src_mac;
		transition select(hdr.ethernet.ether_type) {
			ETHERTYPE_SIDECAR: parse_sidecar;
			ETHERTYPE_VLAN: parse_vlan;
			ETHERTYPE_IPV4: parse_ipv4;
			ETHERTYPE_IPV6: parse_ipv6;
			ETHERTYPE_ARP: parse_arp;
			ETHERTYPE_LLDP: parse_lldp;
			default: accept;
		}
	}

	state parse_sidecar {
		pkt.extract(hdr.sidecar);

		meta.pkt_type = meta.pkt_type | PKT_SIDECAR;
		transition select(hdr.sidecar.sc_ether_type) {
			ETHERTYPE_VLAN: parse_vlan;
			ETHERTYPE_IPV4: parse_ipv4;
			ETHERTYPE_IPV6: parse_ipv6;
			ETHERTYPE_ARP: parse_arp;
			default: accept;
		}
	}

	state parse_vlan {
		pkt.extract(hdr.vlan);

		meta.pkt_type = meta.pkt_type | PKT_VLAN;
		transition select(hdr.vlan.ether_type) {
			ETHERTYPE_IPV4: parse_ipv4;
			ETHERTYPE_IPV6: parse_ipv6;
			ETHERTYPE_ARP: parse_arp;
			default: accept;
		}
	}

	state parse_lldp {
		// All LLDP packets should be routed to the switch zone,
		// where the actual parsing will be done.
		meta.pkt_type = meta.pkt_type | PKT_LLDP;
		meta.is_switch_address = true;
		transition accept;
	}

	state parse_arp {
		meta.pkt_type = meta.pkt_type | PKT_ARP;
		pkt.extract(hdr.arp);
		meta.orig_dst_ipv4 = hdr.arp.target_ip;
		transition accept;
	}

	state parse_ipv4 {
		pkt.extract(hdr.ipv4);
		ipv4_checksum.add(hdr.ipv4);
		meta.orig_src_ipv4 = hdr.ipv4.src_addr;
		meta.orig_dst_ipv4 = hdr.ipv4.dst_addr;
		meta.ipv4_checksum_err = ipv4_checksum.verify();
		meta.pkt_type = meta.pkt_type | PKT_IPV4;

		// This subtracts most of the pseudo header from the checksum.
		// We can't remove the length field yet, because the ipv4
		// header specifies it in words, the pseudo header specifies it
		// in bytes, and p4/tofino will not let us do the math required
		// to convert between the two in the parser.
		nat_checksum.subtract({
			hdr.ipv4.src_addr,
			hdr.ipv4.dst_addr,
			8w0,
			hdr.ipv4.protocol,
		});

		transition select(hdr.ipv4.dst_addr[31:28]) {
			4w0xe: validate_ipv4_mcast1_2;
			default: validate_ttl;
		}
	}

	state validate_ttl {
		transition select(hdr.ipv4.ttl) {
			8w0: invalidate_ttl;
			default: goto_proto_ipv4;
		}
	}

	// IPv4 Multicast Address Validation (RFC 1112, RFC 7042).
	//
	// This validates that IPv4 multicast packets (224.0.0.0/4) use the proper
	// MAC address format:
	//
	// - First byte:  Must be 0x01 (IANA-assigned OUI format)
	// - Second byte: Must be 0x00 (with first bit of second byte being 0)
	// - Third byte:  Must be 0x5e
	// - Last 3 bytes: Must contain the lower 23 bits of the IPv4 multicast
	//   address (with the 24th bit set to 0)
	state validate_ipv4_mcast1_2 {
		// Extract the first byte of the MAC address
		bit<8> mac_byte1 = hdr.ethernet.dst_mac[47:40]; // First byte must be 0x01
		// Extract the second byte of the MAC address
		bit<8> mac_byte2 = hdr.ethernet.dst_mac[39:32]; // Second byte must be 0x00

		transition select(mac_byte1, mac_byte2) {
			(8w0x01, 8w0x00): validate_ipv4_mcast_3;
			default: invalidate_ipv4_mcast;
		}
	}

	// IPv4 Multicast Third Byte Validation
	//
	// Following the IANA mapping rules for IPv4 multicast MAC addresses:
	//
	// - The third byte must always be 0x5e
	// - This completes the IANA OUI prefix (01:00:5e)
	// - After this validation, the remaining 23 bits of the MAC will be
	//   verified against the multicast IPv4 address in the `Filter` control
	state validate_ipv4_mcast_3 {
		// Extract the 3rd byte of the MAC address
		bit<8> mac_byte3 = hdr.ethernet.dst_mac[31:24]; // Third byte must be 0x5e

		transition select(mac_byte3) {
			8w0x5e: set_mcast_ipv4;
			default: invalidate_ipv4_mcast;
		}
	}

	state set_mcast_ipv4 {
		meta.is_mcast = true;
		transition validate_mcast_ttl;
	}

	state validate_mcast_ttl {
		transition select(hdr.ipv4.ttl) {
			8w0: invalidate_ttl;
			8w1: invalidate_ttl;
			default: goto_proto_ipv4;
		}
	}

	state invalidate_ttl {
		meta.drop_reason = DROP_IPV4_TTL_INVALID;
		meta.dropped = true;

		// We don't reject here because we want to update our stats and reason
		transition accept;
	}

	state invalidate_ipv4_mcast {
		meta.is_mcast = true;
		meta.drop_reason = DROP_MULTICAST_INVALID_MAC;
		meta.dropped = true;

		// We don't reject here because we want to update our stats and reason
		transition accept;
	}

	state goto_proto_ipv4 {
		transition select(hdr.ipv4.protocol) {
			IPPROTO_ICMP: parse_icmp;
			IPPROTO_TCP: parse_tcp;
			IPPROTO_UDP: parse_udp;
			default: accept;
		}
	}

	state parse_ipv6 {
		pkt.extract(hdr.ipv6);
		meta.pkt_type = meta.pkt_type | PKT_IPV6;

		nat_checksum.subtract({
			hdr.ipv6.src_addr,
			hdr.ipv6.dst_addr,
			8w0,
			hdr.ipv6.next_hdr,
			hdr.ipv6.payload_len
		});

		transition select(hdr.ipv6.dst_addr[127:112]) {
			16w0xff01: drop_interface_local_mcast;
			16w0xff02: set_link_local_mcast;
			default: check_ipv6_mcast;
		}
	}

	state drop_interface_local_mcast {
		meta.is_mcast = true;
		meta.drop_reason = DROP_MULTICAST_TO_LOCAL_INTERFACE;
		meta.dropped = true;

		// We don't reject here because we want to update our stats and reason
		transition accept;
	}

	state set_link_local_mcast {
		meta.is_link_local_mcastv6 = true;
		meta.is_mcast = true;
		transition validate_mcast_link_local_hop_limit;
	}

	state check_ipv6_mcast {
		// Check if the destination address is a multicast address
		// (ff00::/8) and if the MAC address is in the correct format.
		transition select(hdr.ipv6.dst_addr[127:120]) {
			8w0xff: set_mcast_ipv6;
			default: validate_hop_limit;
		}
	}

	state validate_hop_limit {
		transition select(hdr.ipv6.hop_limit) {
			8w0: invalidate_hop_limit;
			default: goto_proto_ipv6;
		}
	}

	state validate_mcast_link_local_hop_limit {
		// For link-local multicast, we allow a hop limit of 1.
		// This is to ensure that link-local multicast packets
		// are not forwarded beyond the local link.
		transition select(hdr.ipv6.hop_limit) {
			8w0: invalidate_hop_limit;
			8w1: goto_proto_ipv6;
			default: goto_proto_ipv6;
		}
	}

	state validate_mcast_hop_limit {
		transition select(hdr.ipv6.hop_limit) {
			8w0: invalidate_hop_limit;
			8w1: invalidate_hop_limit;
			default: goto_proto_ipv6;
		}
	}

	state set_mcast_ipv6 {
		meta.is_mcast = true;
		transition validate_mcast_hop_limit;
	}

	state invalidate_hop_limit {
		meta.drop_reason = DROP_IPV6_TTL_INVALID;
		meta.dropped = true;

		// We don't reject here because we want to update our stats and reason
		transition accept;
	}

	state goto_proto_ipv6 {
		transition select(hdr.ipv6.next_hdr) {
			IPPROTO_ICMPV6: parse_icmp;
			IPPROTO_TCP: parse_tcp;
			IPPROTO_UDP: parse_udp;
			default: accept;
		}
	}

	state parse_icmp {
		pkt.extract(hdr.icmp);
		meta.pkt_type = meta.pkt_type | PKT_ICMP;

		icmp_checksum.subtract({
			hdr.icmp.hdr_checksum,
			hdr.icmp.type, hdr.icmp.code
		});
		icmp_checksum.subtract_all_and_deposit(meta.icmp_csum);

		nat_checksum.subtract(hdr.icmp);
		nat_checksum.subtract_all_and_deposit(meta.body_checksum);

		transition accept;
	}

	state parse_tcp {
		pkt.extract(hdr.tcp);
		meta.pkt_type = meta.pkt_type | PKT_TCP;

		nat_checksum.subtract(hdr.tcp);
		nat_checksum.subtract_all_and_deposit(meta.body_checksum);

		meta.l4_src_port = hdr.tcp.src_port;
		meta.l4_dst_port = hdr.tcp.dst_port;
		transition accept;
	}

	state parse_udp {
		pkt.extract(hdr.udp);
		meta.pkt_type = meta.pkt_type | PKT_UDP;
		nat_checksum.subtract(hdr.udp);
		nat_checksum.subtract_all_and_deposit(meta.body_checksum);

		meta.l4_src_port = hdr.udp.src_port;
		meta.l4_dst_port = hdr.udp.dst_port;

		transition select(hdr.udp.dst_port) {
			GENEVE_UDP_PORT: parse_geneve;
			default: accept;
		}
	}

	state parse_geneve {
		pkt.extract(hdr.geneve);

		geneve_chunks.set(hdr.geneve.opt_len);

		transition select(hdr.geneve.opt_len) {
			0: geneve_parsed;
			default: parse_geneve_opt;
		}
	}

	state parse_geneve_opt {
		bit<16> curr_opt = pkt.lookahead<bit<16>>();
		transition select(curr_opt) {
			GENEVE_OPT_CLASS_OXIDE: parse_geneve_ox_opt;
			default: geneve_unknown;
		}
	}

	state parse_geneve_ox_opt {
		bit<24> curr_opt = pkt.lookahead<bit<24>>();
		geneve_chunks.decrement(1);

		transition select(curr_opt[6:0]) {
			GENEVE_OPT_OXIDE_EXTERNAL: parse_geneve_ext_tag;
			GENEVE_OPT_OXIDE_MCAST: parse_geneve_mcast_tag;
			GENEVE_OPT_OXIDE_MSS: parse_geneve_mss_tag;
			default: geneve_unknown;
		}
	}

	state parse_geneve_ext_tag {
		pkt.extract(hdr.geneve_opts.oxg_ext_tag);

		transition select (hdr.geneve_opts.oxg_ext_tag.opt_len) {
			0: geneve_opt_parsed;
			_: geneve_malformed;
		}
	}

	state parse_geneve_mcast_tag {
		geneve_chunks.decrement(1);
		pkt.extract(hdr.geneve_opts.oxg_mcast_tag);
		pkt.extract(hdr.geneve_opts.oxg_mcast);

		transition select (hdr.geneve_opts.oxg_mcast_tag.opt_len) {
			1: geneve_opt_parsed;
			_: geneve_malformed;
		}
	}

	state parse_geneve_mss_tag {
		geneve_chunks.decrement(1);
		pkt.extract(hdr.geneve_opts.oxg_mss_tag);
		pkt.extract(hdr.geneve_opts.oxg_mss);

		transition select (hdr.geneve_opts.oxg_mss_tag.opt_len) {
			1: geneve_opt_parsed;
			_: geneve_malformed;
		}
	}

	state geneve_opt_parsed {
		transition select (geneve_chunks.is_zero(), geneve_chunks.is_negative()) {
			(false, false): parse_geneve_opt;
			(true, false): geneve_parsed;
			(false, true): geneve_bad_size;
			// Unreachable.
			default: reject;
		}
	}

	state geneve_malformed {
		meta.drop_reason = DROP_GENEVE_OPTION_MALFORMED;
		meta.dropped = true;
		transition accept;
	}

	state geneve_bad_size {
		meta.drop_reason = DROP_GENEVE_OPTIONS_TOO_LONG;
		meta.dropped = true;
		transition accept;
	}

	// We may, in future, want to varbit every remaining option
	// once we hit one we don't understand, for forward-compatibility.
	state geneve_unknown {
		meta.drop_reason = DROP_GENEVE_OPTION_UNKNOWN;
		meta.dropped = true;
		transition accept;
	}

	state geneve_parsed {
		transition select(hdr.geneve.protocol) {
			GENEVE_ENCAP_ETH: parse_inner_eth;
			ETHERTYPE_IPV4: parse_inner_ipv4;
			ETHERTYPE_IPV6: parse_inner_ipv6;
			default: accept;
		}
	}

	state parse_inner_eth {
		pkt.extract(hdr.inner_eth);
		transition select(hdr.inner_eth.ether_type) {
			ETHERTYPE_IPV4: parse_inner_ipv4;
			ETHERTYPE_IPV6: parse_inner_ipv6;
			default: accept;
		}
	}

	state parse_inner_ipv4 {
		pkt.extract(hdr.inner_ipv4);
		transition select(hdr.inner_ipv4.protocol) {
			IPPROTO_TCP: parse_inner_tcp;
			IPPROTO_UDP: parse_inner_udp;
			IPPROTO_ICMP: parse_inner_icmp;
			default: accept;
		}
	}

	state parse_inner_ipv6 {
		pkt.extract(hdr.inner_ipv6);
		transition select(hdr.inner_ipv6.next_hdr) {
			IPPROTO_TCP: parse_inner_tcp;
			IPPROTO_UDP: parse_inner_udp;
			IPPROTO_ICMPV6: parse_inner_icmp;
			default: accept;
		}
	}

	state parse_inner_tcp {
		pkt.extract(hdr.inner_tcp);
		transition accept;
	}

	state parse_inner_udp {
		pkt.extract(hdr.inner_udp);
		transition accept;
	}

	state parse_inner_icmp {
		pkt.extract(hdr.inner_icmp);
		transition accept;
	}
}

parser EgressParser(
	packet_in pkt,
	out sidecar_headers_t hdr,
	out sidecar_egress_meta_t meta,
	out egress_intrinsic_metadata_t eg_intr_md
) {

	bridge_h bridge_hdr;

	ParserCounter() geneve_chunks;

	state start {
		pkt.extract(eg_intr_md);
		transition meta_init;
	}

	state meta_init {
		meta.drop_reason = 0;
		meta.bridge_hdr.setInvalid();

		meta.decap_ports_0 = 0;
		meta.decap_ports_1 = 0;
		meta.decap_ports_2 = 0;
		meta.decap_ports_3 = 0;
		meta.decap_ports_4 = 0;
		meta.decap_ports_5 = 0;
		meta.decap_ports_6 = 0;
		meta.decap_ports_7 = 0;

		meta.bitmap_result = 0;
		meta.ipv4_checksum_recalc = false;
		meta.vlan_id = 0;
		meta.port_number = 0;


		transition parse_bridge_hdr;
	}

	state parse_bridge_hdr {
		pkt.extract(bridge_hdr);
		meta.bridge_hdr = bridge_hdr;
		meta.bridge_hdr.setValid();

		transition parse_ethernet;
	}

	state parse_ethernet {
		pkt.extract(hdr.ethernet);

		transition select(hdr.ethernet.ether_type) {
			ETHERTYPE_VLAN: parse_vlan;
			ETHERTYPE_IPV4: parse_ipv4;
			ETHERTYPE_IPV6: parse_ipv6;
			default: accept;
		}
	}

	state parse_vlan {
		pkt.extract(hdr.vlan);

		transition select(hdr.vlan.ether_type) {
			ETHERTYPE_IPV4: parse_ipv4;
			ETHERTYPE_IPV6: parse_ipv6;
			default: accept;
		}
	}

	state parse_ipv4 {
		pkt.extract(hdr.ipv4);

		transition select(hdr.ipv4.protocol) {
			IPPROTO_ICMP: parse_icmp;
			IPPROTO_TCP: parse_tcp;
			IPPROTO_UDP: parse_udp;
			default: accept;
		}
	}

	state parse_ipv6 {
		pkt.extract(hdr.ipv6);

		transition select(hdr.ipv6.next_hdr) {
			IPPROTO_TCP: parse_tcp;
			IPPROTO_UDP: parse_udp;
			default: accept;
		}
	}

	state parse_icmp {
		pkt.extract(hdr.icmp);

		transition accept;
	}

	state parse_tcp {
		pkt.extract<tcp_h>(_);

		transition accept;
	}

	state parse_udp {
		pkt.extract(hdr.udp);

		transition select(hdr.udp.dst_port) {
			GENEVE_UDP_PORT: parse_geneve;
			default: accept;
		}
	}

	state parse_geneve {
		pkt.extract(hdr.geneve);

		geneve_chunks.set(hdr.geneve.opt_len);

		transition select(hdr.geneve.opt_len) {
			0: geneve_parsed;
			default: parse_geneve_opt;
		}
	}

	state parse_geneve_opt {
		bit<16> curr_opt = pkt.lookahead<bit<16>>();
		transition select(curr_opt) {
			GENEVE_OPT_CLASS_OXIDE: parse_geneve_ox_opt;
			default: reject;
		}
	}

	state parse_geneve_ox_opt {
		bit<24> curr_opt = pkt.lookahead<bit<24>>();
		geneve_chunks.decrement(1);

		transition select(curr_opt[6:0]) {
			GENEVE_OPT_OXIDE_EXTERNAL: parse_geneve_ext_tag;
			GENEVE_OPT_OXIDE_MCAST: parse_geneve_mcast_tag;
			GENEVE_OPT_OXIDE_MSS: parse_geneve_mss_tag;
			default: reject;
		}
	}

	state parse_geneve_ext_tag {
		pkt.extract(hdr.geneve_opts.oxg_ext_tag);

		transition select (hdr.geneve_opts.oxg_ext_tag.opt_len) {
			0: geneve_opt_parsed;
			_: reject;
		}
	}

	state parse_geneve_mcast_tag {
		geneve_chunks.decrement(1);
		pkt.extract(hdr.geneve_opts.oxg_mcast_tag);
		pkt.extract(hdr.geneve_opts.oxg_mcast);

		transition select (hdr.geneve_opts.oxg_mcast_tag.opt_len) {
			1: geneve_opt_parsed;
			_: reject;
		}
	}

	state parse_geneve_mss_tag {
		geneve_chunks.decrement(1);
		pkt.extract(hdr.geneve_opts.oxg_mss_tag);
		pkt.extract(hdr.geneve_opts.oxg_mss);

		transition select (hdr.geneve_opts.oxg_mss_tag.opt_len) {
			1: geneve_opt_parsed;
			_: reject;
		}
	}

	state geneve_opt_parsed {
		transition select (geneve_chunks.is_zero(), geneve_chunks.is_negative()) {
			(false, false): parse_geneve_opt;
			(true, false): geneve_parsed;
			(false, true): reject;
			// Unreachable.
			default: reject;
		}
	}

	state geneve_parsed {
		transition select(hdr.geneve.protocol) {
			GENEVE_ENCAP_ETH: parse_inner_eth;
			ETHERTYPE_IPV4: parse_inner_ipv4;
			ETHERTYPE_IPV6: parse_inner_ipv6;
			default: accept;
		}
	}

	state parse_inner_eth {
		pkt.extract(hdr.inner_eth);
		transition select(hdr.inner_eth.ether_type) {
			ETHERTYPE_IPV4: parse_inner_ipv4;
			ETHERTYPE_IPV6: parse_inner_ipv6;
			default: accept;
		}
	}

	state parse_inner_ipv4 {
		pkt.extract(hdr.inner_ipv4);
		transition select(hdr.inner_ipv4.protocol) {
			IPPROTO_TCP: parse_inner_tcp;
			IPPROTO_UDP: parse_inner_udp;
			default: accept;
		}
	}

	state parse_inner_ipv6 {
		pkt.extract(hdr.inner_ipv6);
		transition select(hdr.inner_ipv6.next_hdr) {
			IPPROTO_TCP: parse_inner_tcp;
			IPPROTO_UDP: parse_inner_udp;
			default: accept;
		}
	}

	state parse_inner_tcp {
		pkt.extract(hdr.inner_tcp);
		transition accept;
	}

	state parse_inner_udp {
		pkt.extract(hdr.inner_udp);
		transition accept;
	}
}
