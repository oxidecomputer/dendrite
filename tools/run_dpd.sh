#!/bin/bash

# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/
#
# Copyright 2025 Oxide Computer Company

WS=${WS:=`git rev-parse --show-toplevel 2> /dev/null`}
P4_NAME=${P4_NAME:=sidecar}
CHIP_ARCH=tofino2
MODEL=127.0.0.1
PORT_CONFIG="--port-config dpd/misc/model_config.toml"
LISTEN_ADDRESS="--listen-addresses [::1]:12224"
BOARD_REV="b"
MAC_BASE="--mac-base a8:40:25:00:00:02"
GDB=""

function usage() {
	echo "Usage: $0 [-gh] [-b <binary name> ] [-d <P4 directory> [-m <model address> ]"
	echo "\t[-l <human | json> ] [-L <listen address>] [ -M <BASE_MAC> ]"
	echo "\t[-4 <P4 program>] [ -p <port config> ] [ -x <transceiver_interface> ]"
}

while getopts b:d:ghl:m:p:r:t:x:4:L: opt
do
	if [ $opt == "b" ]; then
		BIN_NAME=$OPTARG
	elif [ $opt == "d" ]; then
		P4_DIR=$OPTARG
	elif [ $opt == "g" ]; then
		GDB=gdb --args
	elif [ $opt == "h" ]; then
		usage
		exit 0
	elif [ $opt == "l" ]; then
		LOG_FMT="--log-format $OPTARG"
	elif [ $opt == "m" ]; then
		TOFINO_HOST="TOFINO_HOST=$OPTARG"
	elif [ $opt == "p" ]; then
		if [ $OPTARG == "none" ]; then
			PORT_CONFIG=""
		else
			PORT_CONFIG="--port-config $OPTARG"
		fi
	elif [ $opt == "x" ]; then
		XCVR_CONFIG="--transceiver-interface $OPTARG"
	elif [ $opt == "4" ]; then
		P4_NAME=$OPTARG
	elif [ $opt == "L" ]; then
		LISTEN_ADDRESS="--listen-addresses $OPTARG"
	elif [ $opt == "-M" ]; then
		MAC_BASE="--mac-base $OPTARG"
	else
		usage
		exit 1
	fi
done

if [ x"$P4_DIR" == x ]; then 
	export P4_DIR=`pwd`/target/proto/opt/oxide/dendrite/sidecar
fi

if [ x${SDE} == "x" ]; then
	SDE=/opt/oxide/tofino_sde
fi

if [ x${WS} == "x" ]; then
	# assume we're running from an installed package in /opt/oxide
	export BIN_DIR=/opt/oxide/dendrite/bin
	export ZLOG_CFG=/opt/oxide/dendrite/misc/zlog-cfg
else
	# assume we're running in a workspace
	export BIN_DIR=${WS}/target/debug
	export ZLOG_CFG=${WS}/dpd/misc/zlog-cfg
fi

if [ ! -f ./zlog-cfg-cur ]; then
	if [ ! -f $ZLOG_CFG ]; then
		echo "no ./zlog-cfg-cur or $ZLOG_CFG found"
		exit 1
	fi
	cp $ZLOG_CFG ./zlog-cfg-cur
fi

if [ x"${BIN_NAME}" == "x" ]; then
	if [ ${P4_NAME} == "sidecar" ]; then
		BIN_NAME=dpd
	else
		BIN_NAME=${P4_NAME}d
	fi
fi

echo "Using SDE runtime support at: ${SDE}"
echo

if [ x`uname -o` == xillumos ]; then
	SUDO=pfexec
else
	SUDO=sudo
fi

$SUDO env					\
    P4_NAME=$P4_NAME				\
    P4_DIR=$P4_DIR				\
    $TOFINO_HOST				\
    SIDECAR_BOARD_MAP=sidecar_$BOARD_REV	\
    LD_LIBRARY_PATH=$SDE/lib:$P4_DIR/lib	\
    ${GDB} ${BIN_DIR}/${BIN_NAME} run $PORT_CONFIG	\
    ${LISTEN_ADDRESS} ${LOG_FMT} ${XCVR_CONFIG} \
    ${MAC_BASE}
