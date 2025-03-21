const bit<16> ETHERTYPE_IPV4	= 0x0800;
const bit<16> ETHERTYPE_ARP	= 0x0806;
const bit<16> ETHERTYPE_VLAN	= 0x8100;
const bit<16> ETHERTYPE_LLDP	= 0x88cc;
const bit<16> ETHERTYPE_IPV6	= 0x86dd;
const bit<16> ETHERTYPE_SIDECAR	= 0x0901;

const bit<8> IPPROTO_ICMP	= 1;
const bit<8> IPPROTO_TCP	= 6;
const bit<8> IPPROTO_UDP	= 17;

const bit<8> IPPROTO_HOPOPTS	= 0;
const bit<8> IPPROTO_ROUTING	= 43;
const bit<8> IPPROTO_FRAGMENT	= 44;
const bit<8> IPPROTO_ICMPV6	= 58;

// ICMP message types
const bit<8> ICMP_ECHOREPLY	= 0;
const bit<8> ICMP_DEST_UNREACH	= 3;
const bit<8> ICMP_ECHO		= 8;
const bit<8> ICMP_TIME_EXCEEDED	= 11;

// ICMP error codes
const bit<8> ICMP_EXC_TTL		= 0;
const bit<8> ICMP_EXC_FRAGTIME		= 1;
const bit<8> ICMP_DST_UNREACH_NET	= 0;
const bit<8> ICMP_DST_UNREACH_HOST	= 1;

// ICMPv6 message types
const bit<8> ICMP6_DST_UNREACH		= 1;
const bit<8> ICMP6_PACKET_TOO_BIG	= 2;
const bit<8> ICMP6_TIME_EXCEEDED	= 3;
const bit<8> ICMP6_ECHO			= 128;
const bit<8> ICMP6_ECHOREPLY		= 129;

// ICMPv6 error codes
const bit<8> ICMP6_DST_UNREACH_NOROUTE		= 0;
const bit<8> ICMP6_DST_UNREACH_ADMIN		= 1;
const bit<8> ICMP6_DST_UNREACH_BEYONDSCOPE	= 2;
const bit<8> ICMP6_DST_UNREACH_ADDR		= 3;
const bit<8> ICMP6_DST_UNREACH_NOPORT		= 4;

typedef bit<16> ether_type_t;
typedef bit<48> mac_addr_t;
typedef bit<32> ipv4_addr_t;
typedef bit<128> ipv6_addr_t;
typedef bit<24> geneve_vni_t;

header sidecar_h {
	bit<8>		sc_code;
	bit<8>		sc_pad;
	bit<16>		sc_ingress;
	bit<16>		sc_egress;
	ether_type_t	sc_ether_type;
	bit<128>	sc_payload;
}

header ethernet_h {
	mac_addr_t	dst_mac;
	mac_addr_t	src_mac;
	ether_type_t	ether_type;
}

header dot1q_h {
	bit<3>		pcp;
	bit<1>		dei;
	bit<12>		vlan_id;
	ether_type_t	ether_type;
}

header arp_h {
	bit<16>		hw_type;
	bit<16>		proto_type;
	bit<8>		hw_addr_len;
	bit<8>		proto_addr_len;
	bit<16>		opcode;

	// In theory, the remaining fields should be <varbit>
	// based on the the two x_len fields.
	mac_addr_t	sender_mac;
	ipv4_addr_t	sender_ip;
	mac_addr_t	target_mac;
	ipv4_addr_t	target_ip;
}

header ipv4_h {
	bit<4>		version;
	bit<4>		ihl;
	bit<8>		diffserv;
	bit<16>		total_len;
	bit<16>		identification;
	bit<3>		flags;
	bit<13>		frag_offset;
	bit<8>		ttl;
	bit<8>		protocol;
	bit<16>		hdr_checksum;
	ipv4_addr_t	src_addr;
	ipv4_addr_t	dst_addr;
}

header ipv6_h {
	bit<4>		version;
	bit<8>		traffic_class;
	bit<20>		flow_label;
	bit<16>		payload_len;
	bit<8>		next_hdr;
	bit<8>		hop_limit;
	ipv6_addr_t	src_addr;
	ipv6_addr_t	dst_addr;
}

header tcp_h {
	bit<16> src_port;
	bit<16> dst_port;
	bit<32> seq_no;
	bit<32> ack_no;
	bit<4> data_offset;
	bit<4> res;
	bit<8> flags;
	bit<16> window;
	bit<16> checksum;
	bit<16> urgent_ptr;
}

header udp_h {
	bit<16> src_port;
	bit<16> dst_port;
	bit<16> hdr_length;
	bit<16> checksum;
}

header icmp_h {
	bit<8> type;
	bit<8> code;
	bit<16> hdr_checksum;
	bit<32> data;
}

const bit<16> GENEVE_UDP_PORT	= 6081;
const bit<16> GENEVE_ENCAP_ETH	= 0x6558;

header geneve_h {
	bit<2> version;
	bit<6> opt_len;
	bit<1> ctrl;
	bit<1> crit;
	bit<6> reserved;
	bit<16> protocol;
	geneve_vni_t vni;
	bit<8> reserved2;
}

const bit<16> GENEVE_OPT_CLASS_OXIDE	= 0x0129;
const bit<7> GENEVE_OPT_OXIDE_EXTERNAL	= 0x00;

header geneve_opt_h {
	bit<16> class;
	bit<1> crit;
	bit<7> type;
	bit<3> reserved;
	bit<5> opt_len;
}

// Since we're a TEP, we need to push and read Geneve options.
// `varbit` only allows us to carry.
// XXX: For parsing past one option, add `extern ParserCounter`
//      to oxidecomputer/p4/lang/p4rs/src/externs.rs, consider
//      storing via `header_union`s.
struct geneve_opt_headers_t {
	geneve_opt_h	ox_external_tag;
}

struct sidecar_headers_t {
	ethernet_h	ethernet;
	sidecar_h	sidecar;
	dot1q_h		vlan;
	arp_h		arp;
	ipv4_h		ipv4;
	ipv6_h		ipv6;
	icmp_h		icmp;
	tcp_h		tcp;
	udp_h		udp;

	geneve_h	geneve;
	geneve_opt_headers_t	geneve_opts;
	ethernet_h	inner_eth;
	ipv4_h		inner_ipv4;
	ipv6_h		inner_ipv6;
	icmp_h		inner_icmp;
	tcp_h		inner_tcp;
	udp_h		inner_udp;
}

struct sidecar_ingress_meta_t {
	PortId_t in_port;		// ingress port for this packet

	bool ipv4_checksum_err;		// failed ipv4 checksum
	bool routed;			// packet routed at layer 3
	bool is_switch_address;		// destination IP was a switch port
	bool multicast;			// packet was multicast
	bool service_routed;		// routed to or from a service routine
	bool nat_egress;		// NATed packet from guest -> uplink
	bool nat_ingress;		// NATed packet from uplink -> guest
	bool nat_ingress_port;		// This port accepts only NAT traffic
	ipv4_addr_t nexthop_ipv4;	// ip address of next router
	ipv6_addr_t nexthop_ipv6;	// ip address of next router
	bit<10> pkt_type;
	bit<8> drop_reason;		// reason a packet was dropped

	bit<16> l4_src_port;		// tcp or udp destination port
	bit<16> l4_dst_port;		// tcp or udp destination port
	ipv6_addr_t nat_ingress_tgt;
	mac_addr_t nat_inner_mac;
	geneve_vni_t nat_geneve_vni;

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
