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

control Filter(
	inout sidecar_headers_t hdr,
	inout sidecar_ingress_meta_t meta,
	inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md)
{
	DirectCounter<bit<32>>(CounterType_t.PACKETS_AND_BYTES) ipv4_ctr;
	DirectCounter<bit<32>>(CounterType_t.PACKETS_AND_BYTES) ipv6_ctr;
	bit<16> multicast_scope;

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

	// Table of the IPv4 addresses assigned to ports on the switch.
	table switch_ipv4_addr {
		key = {
			meta.orig_dst_ipv4: exact;
			meta.in_port: ternary;
		}
		actions = { claimv4; dropv4; }

		const size = SWITCH_IPV4_ADDRS_SIZE;
		counters = ipv4_ctr;
	}

	// Table of the IPv6 addresses assigned to ports on the switch.
	table switch_ipv6_addr {
		key = {
			hdr.ipv6.dst_addr: exact;
			meta.in_port: ternary;
		}
		actions = { claimv6; dropv6; }

		const size = SWITCH_IPV6_ADDRS_SIZE;
		counters = ipv6_ctr;
	}


	apply {
		if (hdr.ipv4.isValid() || hdr.arp.isValid()) {
			switch_ipv4_addr.apply();
		} else if (hdr.ipv6.isValid()) {
			multicast_scope = (bit<16>)hdr.ipv6.dst_addr[127:112];
			if (multicast_scope == 16w0xff01) {
				ig_dprsr_md.drop_ctl = 1;
				meta.drop_reason = DROP_MULTICAST_TO_LOCAL_INTERFACE;
			} else {
				meta.multicast = (multicast_scope == 16w0xff02);
				switch_ipv6_addr.apply();
			}
		}
	}
}

// This control checks for packets that require special
// handling rather than being routed  normally.  These
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
	inout ingress_intrinsic_metadata_for_tm_t ig_tm_md)
{
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

		ig_tm_md.ucast_egress_port = meta.in_port;

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

		ig_tm_md.ucast_egress_port = meta.in_port;

		meta.service_routed = true;
	}

	// Send a network service request to a service port.  Push on a
	// sidecar tag, which indicates which port the request arrived on.
	action forward_to_userspace() {
		hdr.sidecar.sc_code = SC_FWD_TO_USERSPACE;
		hdr.sidecar.sc_ingress = (bit<16>)meta.in_port;
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
	// essentially like unicast.  In particular, we don't need to engage
	// the Tofino packet replication mechanism.  "Inbound" multicast
	// packets always go to the service port.  "Outbound" multicast
	// packets always go to the port indicated by the sidecar header.
	action multicast_inbound() {
		hdr.sidecar.sc_code = SC_FWD_TO_USERSPACE;
		hdr.sidecar.sc_ingress = (bit<16>) meta.in_port;
		hdr.sidecar.sc_egress = (bit<16>) ig_tm_md.ucast_egress_port;
		hdr.sidecar.sc_ether_type = hdr.ethernet.ether_type;
		hdr.sidecar.sc_payload = 0;
		hdr.sidecar.setValid();
		hdr.ethernet.ether_type = ETHERTYPE_SIDECAR;
		meta.routed = false;
		meta.service_routed = true;
		ig_tm_md.ucast_egress_port = USER_SPACE_SERVICE_PORT;
		meta.multicast = true;
	}

	table service {
		key = {
		        ig_dprsr_md.drop_ctl: exact;
			meta.nat_ingress: exact;
			meta.multicast: exact;
			meta.is_switch_address: ternary;
			meta.in_port: ternary;
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
			multicast_inbound;
			NoAction;
		}

		const entries = {
			( 0, false, false, true, _, _, false, true, true, false, ICMP_ECHOREPLY, 0 ) : forward_to_userspace;
			( 0, false, false, true, _, _, false, true, true, false, ICMP_ECHOREPLY, _ ) : drop_bad_ping;
			( 0, false, false, true, _, _, false, true, true, false, ICMP_ECHO, 0 ) : ping4_reply;
			( 0, false, false, true, _, _, false, true, true, false, ICMP_ECHO, _ ) : drop_bad_ping;
			( 0, false, false, true, _, _, false, true, false, true, ICMP6_ECHOREPLY, 0 ) : forward_to_userspace;
			( 0, false, false, true, _, _, false, true, false, true, ICMP6_ECHOREPLY, _ ) : drop_bad_ping;
			( 0, false, false, true, _, _, false, true, false, true, ICMP6_ECHO, 0 ) : ping6_reply;
			( 0, false, false, true, _, _, false, true, false, true, ICMP6_ECHO, _ ) : drop_bad_ping;
			( 0, false, false, _, USER_SPACE_SERVICE_PORT, true, _, _, _, _, _, _ ) : forward_from_userspace;
			( 0, false, true, _, USER_SPACE_SERVICE_PORT, true, _, _, _, _, _, _ ) : forward_from_userspace;
			( 0, false, false, _, _, false, true, _, _, _, _, _ ) : forward_to_userspace;
			( 0, false, false, true, _, _, _, _, _, _, _, _ ) : forward_to_userspace;
			( 0, false, true, _, _, _, _, _, _, _, _, _ ) : multicast_inbound;
		}

		default_action = NoAction;
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
		if (!meta.is_switch_address && meta.nat_ingress_port && !meta.nat_ingress) {
			// For packets that were not marked for NAT ingress, but which
			// arrived on an uplink port that only allows in traffic that
			// is meant to be NAT encapsulated.
			meta.drop_reason = DROP_NAT_INGRESS_MISS;
			ig_dprsr_md.drop_ctl = 1;
		} else if (meta.is_switch_address && hdr.geneve.isValid() && hdr.geneve.vni != 0) {
			meta.nat_egress = true;
		} else {
			service.apply();
		}
	}
}

control NatIngress (
	inout sidecar_headers_t hdr,
	inout sidecar_ingress_meta_t meta,
	inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md
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

	action forward_ipv4_to(ipv6_addr_t target, mac_addr_t inner_mac,
	    geneve_vni_t vni) {
		meta.nat_ingress = true;
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
		meta.nat_ingress = true;
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

	// The following actions and table are used to generate the final
	// "length" field in the ipv4 pseudo header, which needs to be backed
	// out of the inner udp/tcp checksums to find the residual for the
	// packet body.  This seems ludicrously complicated, but it's the only
	// way I've found to do the calculation without running afoul of
	// limitations in p4 and/or tofino, governing exactly how much work
	// can be done in each stage and which PHV fields you are allowed
	// to access.  We are using the 'add' action to subtract the size of
	// the IPv4 header.  Why?  Because the p4 compiler will let me add a
	// parameter in an action, but will only let me subtract a constant.
	// So, I can create a single action that will add the negative
	// parameter I've manually computed, or I can create 11 actions, each
	// of which will subtract a hard-coded constant.  Either seems stupid,
	// but here we are.
	// XXX: find a less stupid solution
	action invert() {
		meta.l4_length = ~meta.l4_length;
	}

	action add(bit<16> a) {
		meta.l4_length = hdr.ipv4.total_len + a;
	}

	table ipv4_set_len {
		key = { hdr.ipv4.ihl : exact; }
		actions = { add; }

		const entries = {
			(5) : add(0xffec);
			(6) : add(0xffe8);
			(7) : add(0xffe4);
			(8) : add(0xffe0);
			(9) : add(0xffdc);
			(10) : add(0xffd8);
			(11) : add(0xffd4);
			(12) : add(0xffd0);
			(13) : add(0xffcc);
			(14) : add(0xffc8);
			(15) : add(0xffc4);
		}

		const size = 16;
	}

	action nat_only_port() {
		meta.nat_ingress_port = true;
		nat_only_counter.count();
	}

	table nat_only {
		key = {
			meta.in_port : exact;
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

		if (meta.nat_ingress) {
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
		hdr.geneve_opts.ox_external_tag.setInvalid();
	}

	action decap_ipv4() {
		hdr.ethernet.ether_type = ETHERTYPE_IPV4;
		hdr.ipv4 = hdr.inner_ipv4;
		hdr.ipv4.setValid();
		hdr.inner_ipv4.setInvalid();
	}

	action decap_ipv6() {
		hdr.ethernet.ether_type = ETHERTYPE_IPV6;
		hdr.ipv6 = hdr.inner_ipv6;
		hdr.ipv6.setValid();
		hdr.inner_ipv6.setInvalid();
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
			hdr.inner_ipv4.isValid(): exact;
			hdr.inner_ipv6.isValid(): exact;
			hdr.inner_tcp.isValid(): exact;
			hdr.inner_udp.isValid(): exact;
			hdr.inner_icmp.isValid(): exact;
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
			( false, true, false, true, true ) : decap_ipv6_icmp;
		}
		default_action = drop;

		const size = 6;
	}

	apply {
		if (meta.nat_egress) {
			nat_egress.apply();
		}
	}
}

struct route6_result_t {
	ipv6_addr_t nexthop;
	PortId_t port;
	bool is_hit;
}

control RouterLookup6(
	inout sidecar_headers_t hdr,
	inout sidecar_ingress_meta_t meta,
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
		const size      = IPV6_LPM_SIZE;
		counters	= counter;
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
	inout sidecar_ingress_meta_t meta,
	inout route4_result_t res
) {
	DirectCounter<bit<32>>(CounterType_t.PACKETS_AND_BYTES) index_counter;
	DirectCounter<bit<32>>(CounterType_t.PACKETS_AND_BYTES) forward_counter;

	action forward_vlan(PortId_t port, ipv4_addr_t nexthop, bit<12> vlan_id) {
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
		counters	= forward_counter;
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
		counters	= index_counter;
	}

	apply {
		/*
		 * If the route exists, find the index of its first target in
		 * the target table.
		 */
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
		hdr.sidecar.sc_ingress = (bit<16>) meta.in_port;
		hdr.sidecar.sc_egress = (bit<16>) ig_tm_md.ucast_egress_port;
		hdr.sidecar.sc_ether_type = hdr.ethernet.ether_type;
		hdr.sidecar.sc_payload = (bit<128>) meta.nexthop_ipv4;
		hdr.sidecar.setValid();
		hdr.ethernet.ether_type = ETHERTYPE_SIDECAR;
		meta.routed = false;
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
		hdr.sidecar.sc_ingress = (bit<16>) meta.in_port;
		hdr.sidecar.sc_egress = (bit<16>) ig_tm_md.ucast_egress_port;
		hdr.sidecar.sc_ether_type = hdr.ethernet.ether_type;
		hdr.sidecar.sc_payload = (bit<128>) meta.nexthop_ipv6;
		hdr.sidecar.setValid();
		hdr.ethernet.ether_type = ETHERTYPE_SIDECAR;
		meta.routed = false;
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
	inout ingress_intrinsic_metadata_for_tm_t ig_tm_md
) {
	RouterLookupIndex4() lookup_idx;

	Hash<bit<8>>(HashAlgorithm_t.CRC8) index_hash;

	action icmp_error(bit<8> type, bit<8> code) {
		hdr.sidecar.sc_code = SC_ICMP_NEEDED;
		hdr.sidecar.sc_ingress = (bit<16>) meta.in_port;
		hdr.sidecar.sc_egress = (bit<16>) ig_tm_md.ucast_egress_port;
		hdr.sidecar.sc_ether_type = hdr.ethernet.ether_type;
		hdr.sidecar.sc_payload = (bit<128>)type << 8 | (bit<128>)code;
		hdr.sidecar.setValid();
		hdr.ethernet.ether_type = ETHERTYPE_SIDECAR;
		meta.routed = false;
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

		lookup_idx.apply(hdr, meta, fwd);
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
			meta.routed = true;
			Arp.apply(hdr, meta, ig_dprsr_md, ig_tm_md);
		}
	}
}

control Router6 (
	inout sidecar_headers_t hdr,
	inout sidecar_ingress_meta_t meta,
	inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
	inout ingress_intrinsic_metadata_for_tm_t ig_tm_md
) {
	RouterLookup6() lookup;

	action icmp_error(bit<8> type, bit<8> code) {
		hdr.sidecar.sc_code = SC_ICMP_NEEDED;
		hdr.sidecar.sc_ingress = (bit<16>) meta.in_port;
		hdr.sidecar.sc_egress = (bit<16>) ig_tm_md.ucast_egress_port;
		hdr.sidecar.sc_ether_type = hdr.ethernet.ether_type;
		hdr.sidecar.sc_payload = (bit<128>)type << 8 | (bit<128>)code;
		hdr.sidecar.setValid();
		hdr.ethernet.ether_type = ETHERTYPE_SIDECAR;
		meta.routed = false;
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
		lookup.apply(hdr, meta, fwd);
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
			meta.routed = true;
			Ndp.apply(hdr, meta, ig_dprsr_md, ig_tm_md);
		}
	}
}

control L3Router(
	inout sidecar_headers_t hdr,
	inout sidecar_ingress_meta_t meta,
	inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
	inout ingress_intrinsic_metadata_for_tm_t ig_tm_md
) {
	apply {
		if (hdr.ipv4.isValid()) {
			Router4.apply(hdr, meta, ig_dprsr_md, ig_tm_md);
		} else if (hdr.ipv6.isValid()) {
			Router6.apply(hdr, meta, ig_dprsr_md, ig_tm_md);
		}
	}
}

control MacRewrite(
	inout sidecar_headers_t hdr,
	in sidecar_ingress_meta_t meta,
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
	MacRewrite() mac_rewrite;

	Counter<bit<64>, PortId_t>(512, CounterType_t.PACKETS_AND_BYTES) ingress_ctr;
	Counter<bit<64>, PortId_t>(512, CounterType_t.PACKETS_AND_BYTES) egress_ctr;
	Counter<bit<32>, PortId_t>(512, CounterType_t.PACKETS) drop_port_ctr;
	Counter<bit<32>, bit<8>>(DROP_REASON_MAX, CounterType_t.PACKETS) drop_reason_ctr;
	Counter<bit<32>, bit<10>>(1024, CounterType_t.PACKETS) packet_ctr;

	apply {
		ingress_ctr.count(meta.in_port);
		packet_ctr.count(meta.pkt_type);

		filter.apply(hdr, meta, ig_dprsr_md);
		nat_ingress.apply(hdr, meta, ig_dprsr_md);
		services.apply(hdr, meta, ig_dprsr_md, ig_tm_md);

		if (!meta.service_routed && ig_dprsr_md.drop_ctl == 0) {
			nat_egress.apply(hdr, meta, ig_dprsr_md);
			l3_router.apply(hdr, meta, ig_dprsr_md, ig_tm_md);
		}

		if (meta.drop_reason != 0) {
			drop_port_ctr.count(meta.in_port);
			drop_reason_ctr.count(meta.drop_reason);
		} else if (!meta.multicast) {
			egress_ctr.count(ig_tm_md.ucast_egress_port);
			if (ig_tm_md.ucast_egress_port != USER_SPACE_SERVICE_PORT) {
				mac_rewrite.apply(hdr, meta, ig_tm_md.ucast_egress_port);
			}
			ig_tm_md.bypass_egress = 1w1;
		}
	}
}

// Includes the checksum for the original data, the geneve header, the
// outer udp header, and the outer ipv6 pseudo-header.
// NOTE: safe to include geneve ox_external_tag here as it is filled
// on nat_ingress, and nat_checksum is only computer on nat_ingress.
#define COMMON_FIELDS			\
	meta.body_checksum,		\
	hdr.inner_eth,			\
	hdr.geneve,			\
	hdr.geneve_opts.ox_external_tag,	\
	hdr.udp.src_port,		\
	hdr.udp.dst_port,		\
	hdr.udp.hdr_length,		\
	(bit<16>)hdr.ipv6.next_hdr,	\
	hdr.ipv6.src_addr,		\
	hdr.ipv6.dst_addr,		\
	hdr.ipv6.payload_len

// Includes the final bit of the inner ipv4 pseudo-header and the inner ipv4
// header
#define IPV4_FIELDS			\
	meta.l4_length, 		\
	hdr.inner_ipv4

// Includes the inner ipv6 header
#define IPV6_FIELDS			\
	hdr.inner_ipv6

control IngressDeparser(packet_out pkt,
	inout sidecar_headers_t hdr,
	in sidecar_ingress_meta_t meta,
	in ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md)
{
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

		if (meta.nat_ingress && hdr.inner_ipv4.isValid() &&
		    hdr.inner_udp.isValid()) {
			hdr.udp.checksum = nat_checksum.update({
				COMMON_FIELDS, IPV4_FIELDS, hdr.inner_udp});
		}
		if (meta.nat_ingress && hdr.inner_ipv4.isValid() &&
		    hdr.inner_tcp.isValid()) {
			hdr.udp.checksum = nat_checksum.update({
				COMMON_FIELDS, IPV4_FIELDS, hdr.inner_tcp});
		}
		/* COMPILER BUG: I cannot convince the tofino to compute this correctly.
		 * Conveniently, we dont actually need it, see RFC 6935.
		 *
		 *     if (meta.nat_ingress && hdr.inner_ipv4.isValid() &&
		 *         hdr.inner_icmp.isValid()) {
		 *         hdr.udp.checksum = nat_checksum.update({
		 *             COMMON_FIELDS, IPV4_FIELDS, hdr.inner_icmp});
		 *     }
		 *
		 */
		if (meta.nat_ingress && hdr.inner_ipv6.isValid() &&
		    hdr.inner_udp.isValid()) {
			hdr.udp.checksum = nat_checksum.update({
				COMMON_FIELDS, IPV6_FIELDS, hdr.inner_udp});
		}
		if (meta.nat_ingress && hdr.inner_ipv6.isValid() &&
		    hdr.inner_tcp.isValid()) {
			hdr.udp.checksum = nat_checksum.update({
				COMMON_FIELDS, IPV6_FIELDS, hdr.inner_tcp});
		}
		/* COMPILER BUG: I cannot convince the tofino to compute this correctly.
		 * Conveniently, we dont actually need it, see RFC 6935.
		 *
		 *     if (meta.nat_ingress && hdr.inner_ipv6.isValid() &&
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

struct sidecar_egress_meta_t {}

parser EgressParser(packet_in pkt,
	out sidecar_headers_t hdr,
	out sidecar_egress_meta_t meta,
	out egress_intrinsic_metadata_t eg_intr_md
) {
	state start {
		transition accept;
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
	apply { }
}

control EgressDeparser(packet_out pkt,
	inout sidecar_headers_t hdr,
	in sidecar_egress_meta_t meta,
	in egress_intrinsic_metadata_for_deparser_t eg_dprsr_md
) {
	apply {
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
