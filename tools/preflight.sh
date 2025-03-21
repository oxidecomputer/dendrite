#!/bin/bash

# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/
#
# Copyright 2025 Oxide Computer Company

# This runs most of the operations and tests that are run in CI.
# Running this prior to pushing upstream to github should let you find
# most failures locally, rather than waiting for your turn in the CI
# queue.

set -o errexit
set -o pipefail
set -o xtrace

if [ `uname -s` != SunOS ]; then
	echo $0 must be run on Illumos/Helios
	exit 1
fi

export SDE=${SDE:=/opt/oxide/tofino_sde}

banner "Copyright"
./tools/check_copyrights.sh || exit 1

banner "fmt"
cargo fmt -- --check

cargo build --bin swadm --bin tfportd

for feature in tofino_stub tofino_asic softnpu chaos
do
    NAME=`echo $feature | sed "s/tofino_//"`

    banner build $NAME
    cargo build --features $feature --bin dpd

    banner test $NAME
    # The library path should not be necessary since we are setting rpath
    # in the build.rs, but for some reason the linker only finds libdriver.so
    # and none of the others.
    LD_LIBRARY_PATH=${SDE}/lib cargo test --features $feature

    banner clippy $NAME
    cargo clippy --all-targets --features $feature -- --deny warnings
done
