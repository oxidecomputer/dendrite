#!/bin/bash

# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/
#
# Copyright 2025 Oxide Computer Company

# This simple script is used to build the pre-computed mod table for
# route_selector.p4.  Unless either of the two constants below change,
# we're unlikely to need this again.

# Number of bins in the hash.  Since we're using CRC8, that would be 256.
HASH_SIZE=256
# Maximum number of target slots per route, i.e. the multipath limit.
SLOT_MAX=8

cat << EOF
	action set_slot(bit<8> slot) {
		res.slot = (bit<16>) slot;
	}

	table select_route {
		key = { res.hash: exact; res.slots : exact; }
		actions = { set_slot; }

	const entries = {
EOF

for (( hash=0; hash<$HASH_SIZE; hash++ ))
do
    for (( slots=1; slots<=$SLOT_MAX; slots++ ))
    do
	    idx=$(($hash % $slots))
	    printf "\t\t\t($hash, $slots) : set_slot($idx);\n"
    done
done

SIZE=$(($HASH_SIZE * $SLOT_MAX))
printf "\t\t}\n"
printf "\t\tconst size = $SIZE;\n"
printf "\t}"
