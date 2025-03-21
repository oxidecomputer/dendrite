#!/usr/bin/env bash

# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/
#
# Copyright 2025 Oxide Computer Company

function delete_port() {
    veth0="veth$(($1*2))"
    veth1="veth$(($1*2+1))"

    if /usr/bin/ip link show $veth0 &> /dev/null; then
	    echo Removing $veth0 and $veth1 for port $1
	    # because the veths are created as peers, we only need to delete
	    # one to get rid of both
	    /usr/bin/ip link delete $veth0 type veth
    fi
}

if [ `/usr/bin/id -u` != "0" ]; then
	echo must be run as root
	exit 1
fi

if [ $# -eq 1 ]; then
	ports=$1
else
	ports=64
fi

port_list="`seq 0 $ports` 125"
for port in $port_list; do
	delete_port $port
done
