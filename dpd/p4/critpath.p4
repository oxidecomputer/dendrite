// ry's notes on terrifying nat issue

// we start here
nat_ingress.apply(hdr, meta, ig_intr_md);

// ipv4_ingress_ctr is bumping so we know this action is being taken
action forward_ipv4_to(ipv6_addr_t target, mac_addr_t inner_mac, geneve_vni_t vni) {
	meta.nat_ingress_hit = true;
	meta.nat_ingress_tgt = target;
	meta.nat_inner_mac = inner_mac;
	meta.nat_geneve_vni = vni;
	meta.encap_needed = true;

	ipv4_ingress_ctr.count();
}

// then be cause of a table hit, this happens
if (ingress_hit.apply().hit) {
	if (hdr.ipv4.isValid()) {
		CalculateIPv4Len.apply(hdr, meta);
		encap_ipv4();

// The CalculateIpv4Len looks harmless, on to encap_ipv4
action encap_ipv4() {
	// The forwarded payload is the inner packet plus ethernet, UDP,
	// and Geneve headers (plus external geneve TLV).
	bit<16> payload_len = hdr.ipv4.total_len + 14 + 8 + 8 + 4;

	hdr.inner_ipv4 = hdr.ipv4;
	hdr.inner_ipv4.setValid();
	hdr.ipv4.setInvalid();

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
