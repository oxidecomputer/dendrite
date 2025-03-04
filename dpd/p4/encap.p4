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
