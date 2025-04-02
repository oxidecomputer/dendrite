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
