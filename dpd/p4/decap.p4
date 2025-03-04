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
