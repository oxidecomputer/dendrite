#!/usr/bin/env bash

# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/
#
# Copyright 2025 Oxide Computer Company

function config_veth() {
    /usr/bin/ip link set dev $1 mtu 10240 up

    OPTIONS="rx tx sg tso ufo gso gro lro rxvlan txvlan rxhash"
    for OPTION in $OPTIONS; do
	    /sbin/ethtool --offload $1 $OPTION off &> /dev/null
    done
    sysctl net.ipv6.conf.$1.disable_ipv6=1 &> /dev/null
}
    
function add_port() {
    veth0="veth$(($1*2))"
    veth1="veth$(($1*2+1))"
    echo Adding $veth0 and $veth1 for port $1

    if ! /usr/bin/ip link show $veth0 &> /dev/null; then
	    /usr/bin/ip link add name $veth0 type veth peer name $veth1 &> /dev/null
    fi
    config_veth $veth0
    config_veth $veth1
}

if [ `/usr/bin/id -u` != "0" ]; then
	echo must be run as root
	exit 1
fi

if [ $# -eq 1 ]; then
	ports=$1
else
	ports=16
fi

echo "building veths for $ports ports"

port_list="`seq 0 $ports` 125"
for port in $port_list; do
	add_port $port
done
