#!/bin/bash

# The tofino2 has 20 stages, and the current sidecar.p4 needs all 20 of them.
# Specifying the number of stages isn't strictly necessary, but it allows us to
# track when we exceed the current ceiling. The underlying intention is to grow
# deliberately and thoughtfully, given the limited space on the ASIC.
#
# Note: this now seems silly since we have maxed out the number of stages, but
# we want to leave this check and note in place should we ever find a way to
# reduce our footprint below 20 stages.
TOFINO_STAGES=20

# These describe which version of the SDE to download and where to find it
SDE_COMMIT=b7ae28c7bb6c188b148e6f6494f68dff7d2155e0
SDE_PKG_SHA256=f805e80debc96104d72a87f1ebfa74f00a693a22fddbcf8570350dd3720c20ce
SDE_DEB_SHA256=ef3140875fc3491d22d59673deaaef07846de7a5f5e9c2d42651c2025ebe4199

[ `uname -s` == "SunOS" ] && SERIES=illumos
[ `uname -s` == "SunOS" ] || SERIES=linux
SDE_DIR=https://buildomat.eng.oxide.computer/public/file/oxidecomputer/tofino-sde/$SERIES/$SDE_COMMIT

# Install the active Rust toolchain from rust-toolchain.toml. We need this
# because `rustup` version 1.28 made it where the toolchain is not installed by
# default.
rustup show active-toolchain || rustup toolchain install
