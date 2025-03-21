#!/bin/bash

# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/
#
# Copyright 2025 Oxide Computer Company

declare -a MPL=(
    [0]="This Source Code Form is subject to the terms of the Mozilla Public"
    [1]='License, v. 2.0. If a copy of the MPL was not distributed with this'
    [2]='file, You can obtain one at https://mozilla.org/MPL/2.0/'
)

function check_license {
	local errs=0
	lines=${#MPL[@]}
	for ((i = 0; i < $lines; i++))
	do
		grep -q "${MPL[$i]}" $1 || errs=$((errs+1))
	done

	if [ $errs == 0 ]; then
		return 0
	elif [ $errs == $lines ]; then
		echo $1: Missing license
		return 1
	else
		echo $1: Malformed license
		return 1
	fi
}

function check_copyright {
	MODYEAR=`git log -1 --format=format:%ad --date=format:%Y $1`
	CORRECT="Copyright $MODYEAR Oxide Computer Company"
	ANY="Copyright [0-9]+ Oxide Computer Company"

	grep -q "$CORRECT" $1 && return 0
	egrep -q "$ANY" $1 
	if [ $? == 0 ]; then
		echo $1: Copyright with wrong year
	else
		echo "$1: Missing copyright"
	fi
	return 0
}

FILES=`git ls-files | egrep "\.(sh|xml|rs)$" | grep -v .github`

errs=0
for f in $FILES
do
	check_license $f || errs=$((errs+1))
	check_copyright $f || errs=$((errs+1))
done
exit $errs
