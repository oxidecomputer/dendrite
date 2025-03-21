#!/bin/bash

# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/
#
# Copyright 2025 Oxide Computer Company

# quick sanity check
/usr/bin/ip link show veth2 > /dev/null 2> /dev/null
if [ $? -ne 0 ]; then
	echo missing veth2 device.  Run ./tools/veth_setup.sh
	exit 1
fi

WS=${WS:=`git rev-parse --show-toplevel 2> /dev/null`}
APP_NAME=${APP_NAME:=sidecar}

while getopts p:d:l:t: opt
do
	if [ $opt == "p" ]; then
		APP_NAME=$OPTARG
	elif [ $opt == "d" ]; then
		P4_DIR=$OPTARG
	elif [ $opt == "l" ]; then
		PORT_LAYOUT=$OPTARG
		echo "Usage: $0 [ -p p4 program name ] [ -d p4 directory ]"
		exit 1
	fi
done

# tofino2
CHIP_TYPE=5

# The user can specify the location of the p4 artifacts on the command line
# using the '-d' option.  Otherwise, we will look for them in the local
# dendrite workspace.
if [ x"$P4_DIR" == x ]; then
	P4_DIR=${WS}/target/proto/opt/oxide/dendrite/${APP_NAME}
fi
echo "Looking for p4 artifacts in: $P4_DIR"

CONF=$P4_DIR/${APP_NAME}.conf
if [ ! -f $CONF ]; then
	echo "no p4 config file found at ${CONF}"
	exit 1
fi

if [ x"$SDE" == x ]; then
	SDE=/opt/oxide/tofino_sde
fi
echo "Using Tofino SDE at: $SDE"

# The user can specify a .json file to define the port->veth mapping.  In
# the likely event that the user chooses not to do that, we will try to
# find one in $WS/tools or the installed etc/ directory.  If neither is
# available, we let the model use its default.
if [ x"$PORT_LAYOUT" == x ]; then
	if [ x"$WS" != x ]; then
		PORT_LAYOUT=${WS}/tools/ports_tof2.json
	elif [ -f /opt/oxide/dendrite/etc/ports_tof2.json ]; then
		PORT_LAYOUT=/opt/oxide/dendrite/etc/ports_tof2.json
	else
		PORT_LAYOUT=None
	fi
fi

REMOTE_LIB=${SDE}/lib/remote_model.so
if [ -f $REMOTE_LIB ]; then
	PRELOAD="LD_PRELOAD=${REMOTE_LIB}"
else
	PRELOAD=""
fi

export MODEL=${SDE}/bin/tofino-model
if [ ! -x $MODEL ]; then
	echo no model at: $MODEL
	exit 1
fi

echo "Using config file: ${CONF}"
echo "Using model: ${MODEL}"
echo "Using port layout: ${PORT_LAYOUT}"
echo

sudo env \
	LD_LIBRARY_PATH=$SDE/lib:$LD_LIBRARY_PATH \
	${PRELOAD} \
	${MODEL} \
	-d 1 \
	--p4-target-config $CONF  \
	--install-dir $P4_DIR \
	--chip-type $CHIP_TYPE \
	-f $PORT_LAYOUT \
	--no-cli \
	--use-pcie-veth \
	--port-monitor
